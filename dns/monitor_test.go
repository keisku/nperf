package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestMonitor_ReverseResolve(t *testing.T) {
	type fixuture struct {
		payloads []Payload
		delay    time.Duration
	}
	tests := []struct {
		name              string
		fixuture          fixuture
		addrs             []netip.Addr
		reverseNames      map[netip.Addr]string
		reverseCnames     map[string]string
		wantErr           string
		wantErrAfterDelay string
	}{
		{
			name: "resolved and expired",
			fixuture: fixuture{
				delay: time.Second,
				payloads: []Payload{
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name:  []byte("abc.com"),
									Type:  layers.DNSTypeCNAME,
									CNAME: []byte("efg.com"),
								},
								{
									Name:  []byte("efg.com"),
									Type:  layers.DNSTypeCNAME,
									CNAME: []byte("hij.com"),
								},
								{
									Name: []byte("hij.com"),
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
									Name:  []byte("aaa.com"),
									Type:  layers.DNSTypeCNAME,
									CNAME: []byte("bbb.com"),
								},
								{
									Name: []byte("bbb.com"),
									IP:   []byte{100, 62, 75, 34},
									TTL:  1,
								},
							},
						},
					},
				},
			},
			addrs: []netip.Addr{netip.AddrFrom4([4]byte{169, 62, 75, 34}), netip.AddrFrom4([4]byte{100, 62, 75, 34})},
			reverseNames: map[netip.Addr]string{
				netip.AddrFrom4([4]byte{169, 62, 75, 34}): "abc.com",
				netip.AddrFrom4([4]byte{100, 62, 75, 34}): "aaa.com",
			},
			reverseCnames: map[string]string{
				"hij.com": "efg.com", "efg.com": "abc.com",
				"bbb.com": "aaa.com",
			},
			wantErr:           "",
			wantErrAfterDelay: `domains associsted with the given addresses are not found: [169.62.75.34 100.62.75.34]`,
		},
		{
			name: "resolved and resolved",
			fixuture: fixuture{
				payloads: []Payload{
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
			addrs:             []netip.Addr{netip.AddrFrom4([4]byte{93, 184, 216, 34}), netip.AddrFrom4([4]byte{93, 184, 217, 33})},
			reverseNames:      map[netip.Addr]string{netip.AddrFrom4([4]byte{93, 184, 216, 34}): "www.example.com", netip.AddrFrom4([4]byte{93, 184, 217, 33}): "www.example.com"},
			reverseCnames:     make(map[string]string),
			wantErr:           "",
			wantErrAfterDelay: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Monitor{}
			for _, payload := range tt.fixuture.payloads {
				m.storeAnswers(context.Background(), payload)
			}
			names, cnames, err := m.ReverseResolve(tt.addrs)
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
			if !reflect.DeepEqual(names, tt.reverseNames) {
				t.Errorf("ReverseResolve() = %v, want %v", names, tt.reverseNames)
				return
			}
			if !reflect.DeepEqual(cnames, tt.reverseCnames) {
				t.Errorf("ReverseResolve() = %v, want %v", cnames, tt.reverseCnames)
				return
			}
			<-time.After(tt.fixuture.delay)
			names, cnames, err = m.ReverseResolve(tt.addrs)
			if tt.wantErrAfterDelay == "" {
				if !reflect.DeepEqual(names, tt.reverseNames) {
					t.Errorf("ReverseResolve() = %v, want %v", names, tt.reverseNames)
				}
				if !reflect.DeepEqual(cnames, tt.reverseCnames) {
					t.Errorf("ReverseResolve() = %v, want %v", cnames, tt.reverseCnames)
				}
				return
			} else {
				if err == nil {
					t.Errorf("ReverseResolve() error = %v, wantErr %v", err, tt.wantErrAfterDelay)
				}
				if tt.wantErrAfterDelay != err.Error() {
					t.Errorf("ReverseResolve() error = %v, wantErr %v", err, tt.wantErrAfterDelay)
				}
				count := 0
				m.answers.Range(func(key, value interface{}) bool {
					count++
					return true
				})
				if 0 < count {
					t.Error("ReverseResolve() answers are not cleared after ttl expired")
					count = 0
				}
				m.reverseCnames.Range(func(key, value interface{}) bool {
					count++
					return true
				})
				if 0 < count {
					t.Error("ReverseResolve() cname answers are not cleared after ttl expired")
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
		wantAnswers []answerToDump
	}{
		{
			name: "dump answers",
			fixuture: fixuture{
				getNow: func() time.Time {
					return time.Date(2023, 8, 13, 3, 23, 6, 0, time.UTC)
				},
				payloads: []Payload{
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name:  []byte("abc.com"),
									Type:  layers.DNSTypeCNAME,
									CNAME: []byte("efg.com"),
								},
								{
									Name:  []byte("efg.com"),
									Type:  layers.DNSTypeCNAME,
									CNAME: []byte("hij.com"),
								},
								{
									Name: []byte("hij.com"),
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
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 216, 33},
									TTL:  300,
								},
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
							},
						},
					},
				},
			},
			wantAnswers: []answerToDump{
				{
					answer: answer{
						Name:      "hij.com",
						IPAddr:    netip.AddrFrom4([4]byte{169, 62, 75, 34}),
						TTL:       300 * time.Second,
						ExpiredAt: time.Date(2023, 8, 13, 3, 28, 6, 0, time.UTC),
					},
					Cnames: []string{"efg.com", "abc.com"},
				},
				{
					answer: answer{
						Name:      "www.example.com",
						IPAddr:    netip.AddrFrom4([4]byte{93, 184, 216, 33}),
						TTL:       300 * time.Second,
						ExpiredAt: time.Date(2023, 8, 13, 3, 28, 6, 0, time.UTC),
					},
				},
				{
					answer: answer{
						Name:      "www.example.com",
						IPAddr:    netip.AddrFrom4([4]byte{93, 184, 216, 34}),
						TTL:       300 * time.Second,
						ExpiredAt: time.Date(2023, 8, 13, 3, 28, 6, 0, time.UTC),
					},
				},
				{
					answer: answer{
						Name:      "www.example.com",
						IPAddr:    netip.AddrFrom4([4]byte{93, 184, 217, 33}),
						TTL:       300 * time.Second,
						ExpiredAt: time.Date(2023, 8, 13, 3, 28, 6, 0, time.UTC),
					},
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
			wantAnswers: []answerToDump{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Monitor{}
			getNow = tt.fixuture.getNow
			for _, payload := range tt.fixuture.payloads {
				m.storeAnswers(context.Background(), payload)
			}
			<-time.After(tt.fixuture.delay)
			var w bytes.Buffer
			m.DumpAnswers(&w)
			var gotAnswers []answerToDump
			json.NewDecoder(&w).Decode(&gotAnswers)
			if len(tt.wantAnswers) == 0 && 0 < len(gotAnswers) {
				t.Error("DumpAnswers() = empty, want empty")
			}
			if 0 < len(tt.wantAnswers) && !reflect.DeepEqual(gotAnswers, tt.wantAnswers) {
				t.Errorf("DumpAnswers() = %v, want %v", gotAnswers, tt.wantAnswers)
			}
		})
	}
}
