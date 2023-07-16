package dns

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var _ gopacket.DecodingLayer = &dnsOverTCP{}

// Gopacket doesn't provide direct support for DNS over TCP, see https://github.com/google/gopacket/issues/236
type dnsOverTCP struct {
	layers.TCP
}

// A DNS payload in a TCP segment is preceded by extra two bytes that
// contain the size of the DNS payload. So if the size of the TCP payload
// minus first two bytes equals the DNS payload size, we can safely say
// that the whole of the DNS payload is contained in that single TCP segment.
func (d *dnsOverTCP) hasSelfContainedDNSPayload() bool {
	payload := d.TCP.LayerPayload()
	if len(payload) < 2 {
		return false
	}
	// Assume it's a self-contained DNS message if the Length field
	// matches the length of the TCP segment
	dnsLengthField := binary.BigEndian.Uint16(payload)
	return int(dnsLengthField) == len(payload)-2
}

func (d *dnsOverTCP) NextLayerType() gopacket.LayerType {
	if d.hasSelfContainedDNSPayload() {
		return layers.LayerTypeDNS
	}
	return d.TCP.NextLayerType()
}

func (d *dnsOverTCP) LayerPayload() []byte {
	payload := d.TCP.LayerPayload()
	if len(payload) > 1 {
		// Omit the DNS length field, only included
		// in TCP, in order to reuse the DNS UDP parser
		payload = payload[2:]
	}
	return payload
}
