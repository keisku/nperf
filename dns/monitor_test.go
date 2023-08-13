package dns

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestMonitor_DumpAnswers(t *testing.T) {
	type fixuture struct {
		payloads []Payload
		getNow   func() time.Time
		delay    time.Duration
	}
	tests := []struct {
		name        string
		fixuture    fixuture
		wantAnswers []Answer
	}{
		{
			name: "normal",
			fixuture: fixuture{
				getNow: func() time.Time {
					return time.Date(2023, 8, 13, 3, 23, 6, 0, time.UTC)
				},
				payloads: []Payload{
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name: []byte("zzz.com"),
									IP:   []byte{169, 62, 75, 34},
									TTL:  300,
								},
							},
						},
					},
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name: []byte("github.com"),
									IP:   []byte{20, 27, 177, 113},
									TTL:  300,
								},
								{
									Name: []byte("github.com"),
									IP:   []byte{20, 27, 177, 114},
									TTL:  300,
								},
							},
						},
					},
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 216, 34},
									TTL:  300,
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 217, 33},
									TTL:  300,
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{94, 184, 216, 34},
									TTL:  300,
								},
							},
						},
					},
				},
			},
			wantAnswers: []Answer{
				{
					Name: "github.com",
					IPAddrs: []netip.Addr{
						netip.AddrFrom4([4]byte{20, 27, 177, 113}),
						netip.AddrFrom4([4]byte{20, 27, 177, 114}),
					},
					TTL:       300 * time.Second,
					ExpiredAt: time.Date(2023, 8, 13, 3, 28, 6, 0, time.UTC),
				},
				{
					Name: "www.example.com",
					IPAddrs: []netip.Addr{
						netip.AddrFrom4([4]byte{93, 184, 216, 34}),
						netip.AddrFrom4([4]byte{93, 184, 217, 33}),
						netip.AddrFrom4([4]byte{94, 184, 216, 34}),
					},
					TTL:       300 * time.Second,
					ExpiredAt: time.Date(2023, 8, 13, 3, 28, 6, 0, time.UTC),
				},
				{
					Name: "zzz.com",
					IPAddrs: []netip.Addr{
						netip.AddrFrom4([4]byte{169, 62, 75, 34}),
					},
					TTL:       300 * time.Second,
					ExpiredAt: time.Date(2023, 8, 13, 3, 28, 6, 0, time.UTC),
				},
			},
		},
		{
			name: "ttl expired",
			fixuture: fixuture{
				getNow: time.Now,
				delay:  time.Second,
				payloads: []Payload{
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name: []byte("zzz.com"),
									IP:   []byte{169, 62, 75, 34},
									TTL:  1,
								},
							},
						},
					},
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name: []byte("github.com"),
									IP:   []byte{20, 27, 177, 113},
									TTL:  1,
								},
								{
									Name: []byte("github.com"),
									IP:   []byte{20, 27, 177, 114},
									TTL:  1,
								},
							},
						},
					},
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 216, 34},
									TTL:  1,
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 217, 33},
									TTL:  1,
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{94, 184, 216, 34},
									TTL:  1,
								},
							},
						},
					},
				},
			},
			wantAnswers: []Answer{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var syncMap sync.Map
			m := &Monitor{
				answers: syncMap,
			}
			getNow = tt.fixuture.getNow
			for _, payload := range tt.fixuture.payloads {
				m.storeDomains(context.Background(), payload)
			}
			<-time.After(tt.fixuture.delay)
			var w bytes.Buffer
			m.DumpAnswers(&w)
			var gotAnswers []Answer
			json.NewDecoder(&w).Decode(&gotAnswers)
			if !reflect.DeepEqual(gotAnswers, tt.wantAnswers) {
				t.Errorf("DumpAnswers() = %v, want %v", gotAnswers, tt.wantAnswers)
			}
		})
	}
}
