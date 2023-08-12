package dns

import (
	"context"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestMonitor_ReverseResolve(t *testing.T) {
	type fixuture struct {
		payload Payload
	}
	type args struct {
		addrs []netip.Addr
	}
	tests := []struct {
		name     string
		fixuture fixuture
		args     args
		want     map[netip.Addr]string
		wantErr  string
	}{
		{
			name: "not resolved",
			fixuture: fixuture{
				payload: Payload{
					DNS: &layers.DNS{
						Answers: []layers.DNSResourceRecord{
							{
								Name: []byte("github.com"),
								IP:   []byte{20, 27, 177, 113},
								TTL:  1,
							},
						},
					},
				},
			},
			args: args{
				addrs: []netip.Addr{
					netip.AddrFrom4([4]byte{127, 0, 0, 1}),
				},
			},
			want:    nil,
			wantErr: "domains associsted with the given addresses are not found: [127.0.0.1]",
		},
		{
			name: "resolved and ttl expired",
			fixuture: fixuture{
				payload: Payload{
					DNS: &layers.DNS{
						Answers: []layers.DNSResourceRecord{
							{
								Name: []byte("www.example.com"),
								IP:   []byte{93, 184, 216, 34},
								TTL:  1,
							},
						},
					},
				},
			},
			args: args{
				addrs: []netip.Addr{
					netip.AddrFrom4([4]byte{93, 184, 216, 34}),
				},
			},
			want: map[netip.Addr]string{
				netip.AddrFrom4([4]byte{93, 184, 216, 34}): "www.example.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var syncMap sync.Map
			m := &Monitor{
				answers: syncMap,
			}
			m.storeDomains(context.Background(), tt.fixuture.payload)
			got, err := m.ReverseResolve(tt.args.addrs)
			if err == nil {
				if tt.wantErr != "" {
					t.Errorf("ReverseResolve() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			} else {
				if tt.wantErr != err.Error() {
					t.Errorf("ReverseResolve() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReverseResolve() = %v, want %v", got, tt.want)
			}
			for _, ans := range tt.fixuture.payload.Answers {
				<-time.After(time.Duration(ans.TTL) * time.Second)
				v, _ := m.ReverseResolve(tt.args.addrs)
				if len(v) != 0 {
					t.Errorf("domain cache is not removed")
				}
			}
		})
	}
}
