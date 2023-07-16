package dns

import (
	"net/netip"

	"github.com/google/gopacket/layers"
	"github.com/keisku/nmon/util/intern"
	"golang.org/x/exp/slog"
)

type Packet struct {
	transactionID uint16
	key           Key
	// typ tells us whether the packet is a query or a reply (successful/failed)
	typ          packetType
	responseCode layers.DNSResponseCode
	// question is the query that was sent to the DNS server.
	question  Hostname
	queryType layers.DNSType
}

func (p *Packet) LogAttr() slog.Attr {
	return slog.Group(
		"dns packet",
		slog.Any("transaction_id", p.transactionID),
		slog.Group(
			"key",
			slog.String("server_ip", p.key.serverIP.String()),
			slog.String("client_ip", p.key.clientIP.String()),
			slog.Any("client_port", p.key.clientPort),
			slog.Any("protocol", p.key.protocol),
		),
		"type", p.typ,
		"response_code", p.responseCode.String(),
		"question", p.question.Get(),
		"query_type", p.queryType.String(),
	)
}

// Key is an identifier for a set of DNS connections
type Key struct {
	serverIP   netip.Addr
	clientIP   netip.Addr
	clientPort uint16
	// Protocol will be either TCP or UDP
	protocol uint8
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
