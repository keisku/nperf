package dns

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/keisku/nperf/metric"
	"go.opentelemetry.io/otel/attribute"
)

var (
	errTruncated      = errors.New("the packet is truncated")
	errSkippedPayload = errors.New("the packet does not contain relevant DNS response")
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

func newParser() *parser {
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
	return &parser{
		decoder:     gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, decoders...),
		ipv4Payload: ipv4Payload,
		ipv6Payload: ipv6Payload,
		udpPayload:  udpPayload,
		tcpPayload:  tcpPayload,
		dnsPayload:  dnsPayload,
		recodedQueryTypes: map[layers.DNSType]struct{}{
			layers.DNSTypeA:     {},
			layers.DNSTypeAAAA:  {},
			layers.DNSTypeCNAME: {},
		},
	}
}

func (p *parser) parse(data []byte, payload *Payload) error {
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
	if len(p.dnsPayload.Questions) != 1 {
		metric.Inc(metric.DNSParseDNSLayerSkip)
		return errSkippedPayload
	}
	question := p.dnsPayload.Questions[0]
	if question.Class != layers.DNSClassIN || !p.wantQueryType(question.Type) {
		metric.Inc(metric.DNSParseDNSLayerSkip)
		return errSkippedPayload
	}
	if p.dnsPayload.ResponseCode != layers.DNSResponseCodeNoErr {
		metric.Inc(metric.DNSResponseFailure, attribute.String("response_code", p.dnsPayload.ResponseCode.String()))
	}
	payload.DNS = p.dnsPayload
	for _, layer := range p.layers {
		switch layer {
		case layers.LayerTypeIPv4:
			if err := p.parseIpAddr(payload, p.ipv4Payload); err != nil {
				metric.Inc(metric.DNSParseIPLayerError, []attribute.KeyValue{
					attribute.String("error", err.Error()),
					attribute.Int("ip_version", 4),
				}...)
				slog.Warn("failed to parse IPv4 addresses", "error", err)
			}
		case layers.LayerTypeIPv6:
			if err := p.parseIpAddr(payload, p.ipv6Payload); err != nil {
				metric.Inc(metric.DNSParseIPLayerError, []attribute.KeyValue{
					attribute.String("error", err.Error()),
					attribute.Int("ip_version", 6),
				}...)
				slog.Warn("failed to parse IPv6 addresses", "error", err)
			}
		case layers.LayerTypeUDP:
			if payload.QR {
				payload.connection.clientPort = uint16(p.udpPayload.DstPort)
			} else {
				payload.connection.clientPort = uint16(p.udpPayload.SrcPort)
			}
			payload.connection.protocol = syscall.IPPROTO_UDP
		case layers.LayerTypeTCP:
			if payload.QR {
				payload.connection.clientPort = uint16(p.tcpPayload.DstPort)
			} else {
				payload.connection.clientPort = uint16(p.tcpPayload.SrcPort)
			}
			payload.connection.protocol = syscall.IPPROTO_TCP
		}
	}
	return nil
}

func (*parser) parseIpAddr(payload *Payload, layer gopacket.DecodingLayer) error {
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
	if payload.QR {
		payload.connection.clientIP = dstIp
		payload.connection.serverIP = srcIp
	} else {
		payload.connection.clientIP = srcIp
		payload.connection.serverIP = dstIp
	}
	return nil
}

func (p *parser) wantQueryType(checktype layers.DNSType) bool {
	_, ok := p.recodedQueryTypes[checktype]
	return ok
}
