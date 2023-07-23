package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/exp/slog"
)

// packetType tells us whether the packet is a query or a reply (successful/failed)
type packetType uint8

const (
	// successfulResponse means the packet contains a DNS response and the response code is 0 (no error)
	packetTypeSuccessfulResponse packetType = iota
	// failedResponse means the packet contains a DNS response and the response code is not 0
	packetTypeFailedResponse
	// query means the packet contains a DNS query
	packetTypeQuery
)

func (t packetType) String() string {
	switch t {
	case packetTypeSuccessfulResponse:
		return "successful_response"
	case packetTypeFailedResponse:
		return "failed_response"
	case packetTypeQuery:
		return "query"
	default:
		return "unknown"
	}
}

var (
	errTruncated      = errors.New("the packet is truncated")
	errSkippedPayload = errors.New("the packet does not contain relevant DNS response")

	queryTypeStringMap = map[string]layers.DNSType{
		layers.DNSTypeA.String():     layers.DNSTypeA,
		layers.DNSTypeNS.String():    layers.DNSTypeNS,
		layers.DNSTypeMD.String():    layers.DNSTypeMD,
		layers.DNSTypeMF.String():    layers.DNSTypeMF,
		layers.DNSTypeCNAME.String(): layers.DNSTypeCNAME,
		layers.DNSTypeSOA.String():   layers.DNSTypeSOA,
		layers.DNSTypeMB.String():    layers.DNSTypeMB,
		layers.DNSTypeMG.String():    layers.DNSTypeMG,
		layers.DNSTypeMR.String():    layers.DNSTypeMR,
		layers.DNSTypeNULL.String():  layers.DNSTypeNULL,
		layers.DNSTypeWKS.String():   layers.DNSTypeWKS,
		layers.DNSTypePTR.String():   layers.DNSTypePTR,
		layers.DNSTypeHINFO.String(): layers.DNSTypeHINFO,
		layers.DNSTypeMINFO.String(): layers.DNSTypeMINFO,
		layers.DNSTypeMX.String():    layers.DNSTypeMX,
		layers.DNSTypeTXT.String():   layers.DNSTypeTXT,
		layers.DNSTypeAAAA.String():  layers.DNSTypeAAAA,
		layers.DNSTypeSRV.String():   layers.DNSTypeSRV,
		layers.DNSTypeOPT.String():   layers.DNSTypeOPT,
		layers.DNSTypeURI.String():   layers.DNSTypeURI,
	}
)

// The parser struct contains the necessary components to parse a DNS packet.
// This is the main structure that is used to handle and parse DNS packets.
type parser struct {
	decoder           *gopacket.DecodingLayerParser
	layers            []gopacket.LayerType
	ipv4Payload       *layers.IPv4
	ipv6Payload       *layers.IPv6
	udpPayload        *layers.UDP
	tcpPayload        *dnsOverTCP
	dnsPayload        *layers.DNS
	recodedQueryTypes map[layers.DNSType]struct{}
}

func newParser(queryTypes []string) *parser {
	ipv4Payload := &layers.IPv4{}
	ipv6Payload := &layers.IPv6{}
	udpPayload := &layers.UDP{}
	tcpPayload := &dnsOverTCP{}
	dnsPayload := &layers.DNS{}
	decoders := []gopacket.DecodingLayer{
		&layers.Ethernet{},
		ipv4Payload,
		ipv6Payload,
		udpPayload,
		tcpPayload,
		dnsPayload,
	}
	var qtypes strings.Builder
	recodedQueryTypes := map[layers.DNSType]struct{}{
		layers.DNSTypeA: {},
	}
	qtypes.WriteString(layers.DNSTypeA.String())
	for _, qt := range queryTypes {
		if dnsType, ok := queryTypeStringMap[qt]; ok {
			recodedQueryTypes[dnsType] = struct{}{}
			qtypes.WriteString(fmt.Sprintf(", %s", dnsType.String()))
		} else {
			slog.Warn(fmt.Sprintf("unknown DNS query type %q", qt))
		}
	}
	slog.Info(fmt.Sprintf("DNS Monitor will record queries of type %q", qtypes.String()))
	return &parser{
		decoder:           gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, decoders...),
		ipv4Payload:       ipv4Payload,
		ipv6Payload:       ipv6Payload,
		udpPayload:        udpPayload,
		tcpPayload:        tcpPayload,
		dnsPayload:        dnsPayload,
		recodedQueryTypes: recodedQueryTypes,
	}
}

func (p *parser) parse(data []byte, packet *Packet) error {
	err := p.decoder.DecodeLayers(data, &p.layers)
	if p.decoder.Truncated {
		return errTruncated
	}
	if err != nil {
		return fmt.Errorf("decoding layers: %s", err)
	}
	// If there is a DNS layer then it would be the last layer
	if p.layers[len(p.layers)-1] != layers.LayerTypeDNS {
		return errSkippedPayload
	}
	if err := p.parseAnswer(p.dnsPayload, packet); err != nil {
		if err != errSkippedPayload {
			parseDNSLayerError.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error", err.Error())))
		}
		return fmt.Errorf("parsing DNS answer: %s", err)
	}
	for _, layer := range p.layers {
		switch layer {
		case layers.LayerTypeIPv4:
			if err := p.parseIpAddr(packet, p.ipv4Payload); err != nil {
				parseIPLayerError.Add(context.Background(), 1, metric.WithAttributes(
					attribute.String("error", err.Error()),
					attribute.Int("ip_version", 4),
				))
				slog.Warn("failed to parse IPv4 addresses", "error", err)
			}
		case layers.LayerTypeIPv6:
			if err := p.parseIpAddr(packet, p.ipv6Payload); err != nil {
				parseIPLayerError.Add(context.Background(), 1, metric.WithAttributes(
					attribute.String("error", err.Error()),
					attribute.Int("ip_version", 6),
				))
				slog.Warn("failed to parse IPv6 addresses", "error", err)
			}
		case layers.LayerTypeUDP:
			if packet.typ == packetTypeQuery {
				packet.key.clientPort = uint16(p.udpPayload.SrcPort)
			} else {
				packet.key.clientPort = uint16(p.udpPayload.DstPort)
			}
			packet.key.protocol = syscall.IPPROTO_UDP
		case layers.LayerTypeTCP:
			if packet.typ == packetTypeQuery {
				packet.key.clientPort = uint16(p.udpPayload.SrcPort)
			} else {
				packet.key.clientPort = uint16(p.udpPayload.DstPort)
			}
			packet.key.protocol = syscall.IPPROTO_TCP
		}
	}
	packet.transactionID = p.dnsPayload.ID
	return nil
}

// parseIpAddr parses the IP address from the layer.
// This is used to extract the IP address from the layer for further processing.
func (*parser) parseIpAddr(packet *Packet, layer gopacket.DecodingLayer) error {
	var rawSrcIp, rawDstIp []byte
	switch l := layer.(type) {
	case *layers.IPv4:
		rawSrcIp = l.SrcIP
		rawDstIp = l.DstIP
	case *layers.IPv6:
		rawSrcIp = l.SrcIP
		rawDstIp = l.DstIP
	default:
		return fmt.Errorf("unexpected layer type %T", layer)
	}
	srcIp, ok := netip.AddrFromSlice(rawSrcIp)
	if !ok {
		return fmt.Errorf("parse source IP address: %s", rawSrcIp)
	}
	dstIp, ok := netip.AddrFromSlice(rawDstIp)
	if !ok {
		return fmt.Errorf("parse destination IP address: %s", rawDstIp)
	}
	if packet.typ == packetTypeQuery {
		packet.key.clientIP = srcIp
		packet.key.serverIP = dstIp
	} else {
		packet.key.clientIP = dstIp
		packet.key.serverIP = srcIp
	}
	return nil
}

func (p *parser) wantQueryType(checktype layers.DNSType) bool {
	_, ok := p.recodedQueryTypes[checktype]
	return ok
}

// parseAnswer parses the answer from the DNS layer.
// This is used to extract the answer from the DNS layer for further processing.
func (p *parser) parseAnswer(dns *layers.DNS, packet *Packet) error {
	// Only consider singleton, A-record questions
	if len(dns.Questions) != 1 {
		return errSkippedPayload
	}
	question := dns.Questions[0]
	if question.Class != layers.DNSClassIN || !p.wantQueryType(question.Type) {
		return errSkippedPayload
	}
	if !dns.QR {
		packet.typ = packetTypeQuery
		packet.queryType = question.Type
		packet.question = hostnameFromBytes(question.Name)
		return nil
	}
	packet.responseCode = dns.ResponseCode
	if dns.ResponseCode != 0 {
		responseFailure.Add(context.Background(), 1, metric.WithAttributes(attribute.String("response_code", dns.ResponseCode.String())))
		packet.typ = packetTypeFailedResponse
		return nil
	}
	packet.queryType = question.Type
	packet.typ = packetTypeSuccessfulResponse
	return nil
}
