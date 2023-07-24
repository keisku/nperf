package dns

import (
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/keisku/nmon/util/intern"
	"go.opentelemetry.io/otel/attribute"
)

type Packet struct {
	transactionID uint16
	key           Key
	// typ tells us whether the packet is a query or a reply (successful/failed)
	typ          packetType
	responseCode layers.DNSResponseCode
	// question is the query that was sent to the DNS server.
	question   Hostname
	queryType  layers.DNSType
	capturedAt time.Time
}

func (p *Packet) Attributes() []attribute.KeyValue {
	return append([]attribute.KeyValue{
		// NOTE:
		// - Don't add the transaction ID to the attributes because it's high cardinality.
		// - Don't add the query_type/question to the attributes because a dns answer packet doesn't have.
		attribute.String("type", p.typ.String()),
		attribute.String("response_code", p.responseCode.String()),
	}, p.key.Attributes()...)
}

// Key is an identifier for a set of DNS connections
type Key struct {
	serverIP   netip.Addr
	clientIP   netip.Addr
	clientPort uint16
	// Protocol will be either TCP or UDP
	protocol uint8
}

func (k Key) Attributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("server_ip", k.serverIP.String()),
		attribute.String("client_ip", k.clientIP.String()),
		attribute.Int("client_port", int(k.clientPort)),
		attribute.Int("protocol", int(k.protocol)),
	}
}

var si = intern.NewStringInterner()

// Hostname represents a DNS hostname (aka domain name)
type Hostname = *intern.StringValue

// ToString converts a dns.Hostname to a string
func toString(h Hostname) string {
	return h.Get()
}

// HostnameFromBytes converts a byte slice representing a hostname to a dns.Hostname
func hostnameFromBytes(b []byte) Hostname {
	return si.Get(b)
}

// ToHostname converts from a string to a dns.Hostname
func toHostname(s string) Hostname {
	return si.GetString(s)
}
