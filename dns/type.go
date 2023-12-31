package dns

import (
	"net/netip"

	"github.com/google/gopacket/layers"
	"go.opentelemetry.io/otel/attribute"
)

type Payload struct {
	*layers.DNS
	connection Connection
}

func (p *Payload) Attributes() []attribute.KeyValue {
	return append([]attribute.KeyValue{
		// NOTE:
		// - Don't add the transaction ID to the attributes because it's high cardinality.
		// - Don't add the query_type/question to the attributes because a dns answer packet doesn't have.
		attribute.String("response_code", p.ResponseCode.String()),
	}, p.connection.Attributes()...)
}

// An identifier for a set of DNS connections
type Connection struct {
	daddr netip.Addr
	saddr netip.Addr
	sport uint16
	// Protocol will be either TCP or UDP
	protocol uint8
}

func (c Connection) Attributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("daddr", c.daddr.String()),
		attribute.String("saddr", c.saddr.String()),
		attribute.Int("sport", int(c.sport)),
		attribute.Int("protocol", int(c.protocol)),
	}
}
