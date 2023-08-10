package utilnetip

import (
	"encoding/binary"
	"net/netip"
)

// FromLowHigh creates an address from a pair of uint64 numbers
func FromLowHigh(l, h uint64) netip.Addr {
	if h > 0 {
		return V6Address(l, h)
	}

	return V4Address(uint32(l))
}

// V6Address creates an Address using the uint128 representation of an v6 IP
func V6Address(low, high uint64) netip.Addr {
	var a [16]byte
	binary.LittleEndian.PutUint64(a[:8], high)
	binary.LittleEndian.PutUint64(a[8:], low)
	return netip.AddrFrom16(a)
}

// V4Address creates an Address using the uint32 representation of an v4 IP
func V4Address(ip uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		uint8(ip),
		uint8(ip >> 8),
		uint8(ip >> 16),
		uint8(ip >> 24),
	})
}
