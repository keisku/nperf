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
		ttl      time.Duration
	}
	tests := []struct {
		name                string
		fixuture            fixuture
		addrs               []netip.Addr
		reverseNames        map[netip.Addr]string
		reverseCnames       map[string]string
		wantErr             string
		wantErrAfterExpired string
	}{
		{
			name: "resolved and expired",
			fixuture: fixuture{
				ttl: 100 * time.Millisecond,
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
			wantErr:             "",
			wantErrAfterExpired: `domains associsted with the given addresses are not found: [169.62.75.34 100.62.75.34]`,
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
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 217, 33},
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{94, 184, 216, 34},
								},
							},
						},
					},
				},
			},
			addrs:               []netip.Addr{netip.AddrFrom4([4]byte{93, 184, 216, 34}), netip.AddrFrom4([4]byte{93, 184, 217, 33})},
			reverseNames:        map[netip.Addr]string{netip.AddrFrom4([4]byte{93, 184, 216, 34}): "www.example.com", netip.AddrFrom4([4]byte{93, 184, 217, 33}): "www.example.com"},
			reverseCnames:       make(map[string]string),
			wantErr:             "",
			wantErrAfterExpired: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				answerTTL = time.Minute
			})
			m := &Monitor{}
			if 0 < tt.fixuture.ttl {
				answerTTL = tt.fixuture.ttl
			}
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
			if tt.wantErrAfterExpired != "" {
				<-time.After(answerTTL)
			}
			names, cnames, err = m.ReverseResolve(tt.addrs)
			if tt.wantErrAfterExpired == "" {
				if !reflect.DeepEqual(names, tt.reverseNames) {
					t.Errorf("ReverseResolve() = %v, want %v", names, tt.reverseNames)
				}
				if !reflect.DeepEqual(cnames, tt.reverseCnames) {
					t.Errorf("ReverseResolve() = %v, want %v", cnames, tt.reverseCnames)
				}
				return
			} else {
				if err == nil {
					t.Errorf("ReverseResolve() error = %v, wantErr %v", err, tt.wantErrAfterExpired)
					return
				}
				if tt.wantErrAfterExpired != err.Error() {
					t.Errorf("ReverseResolve() error = %v, wantErr %v", err, tt.wantErrAfterExpired)
					return
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
		payloads    []Payload
		ttl         time.Duration
		shouldDelay bool
		getNow      func() time.Time
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
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 216, 34},
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 217, 33},
								},
							},
						},
					},
				},
			},
			wantAnswers: []answerToDump{
				{
					answer: answer{
						Name:      "abc.com",
						IPAddr:    netip.AddrFrom4([4]byte{169, 62, 75, 34}),
						ExpiredAt: time.Date(2023, 8, 13, 3, 24, 6, 0, time.UTC),
					},
					Cnames: []string{"hij.com", "efg.com"},
				},
				{
					answer: answer{
						Name:      "www.example.com",
						IPAddr:    netip.AddrFrom4([4]byte{93, 184, 216, 33}),
						ExpiredAt: time.Date(2023, 8, 13, 3, 24, 6, 0, time.UTC),
					},
				},
				{
					answer: answer{
						Name:      "www.example.com",
						IPAddr:    netip.AddrFrom4([4]byte{93, 184, 216, 34}),
						ExpiredAt: time.Date(2023, 8, 13, 3, 24, 6, 0, time.UTC),
					},
				},
				{
					answer: answer{
						Name:      "www.example.com",
						IPAddr:    netip.AddrFrom4([4]byte{93, 184, 217, 33}),
						ExpiredAt: time.Date(2023, 8, 13, 3, 24, 6, 0, time.UTC),
					},
				},
			},
		},
		{
			name: "ttl expired",
			fixuture: fixuture{
				ttl:         time.Millisecond,
				shouldDelay: true,
				payloads: []Payload{
					{
						DNS: &layers.DNS{
							Answers: []layers.DNSResourceRecord{
								{
									Name: []byte("zzz.com"),
									IP:   []byte{169, 62, 75, 34},
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
								},
								{
									Name: []byte("github.com"),
									IP:   []byte{20, 27, 177, 114},
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
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{93, 184, 217, 33},
								},
								{
									Name: []byte("www.example.com"),
									IP:   []byte{94, 184, 216, 34},
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
			t.Cleanup(func() {
				answerTTL = time.Minute
				getNow = time.Now
			})
			m := &Monitor{}
			if tt.fixuture.getNow != nil {
				getNow = tt.fixuture.getNow
			}
			if 0 < tt.fixuture.ttl {
				answerTTL = tt.fixuture.ttl
			}
			for _, payload := range tt.fixuture.payloads {
				m.storeAnswers(context.Background(), payload)
			}
			if tt.fixuture.shouldDelay {
				<-time.After(answerTTL)
			}
			var w bytes.Buffer
			m.DumpAnswers(&w)
			var gotAnswers []answerToDump
			json.NewDecoder(&w).Decode(&gotAnswers)
			if len(tt.wantAnswers) == 0 && 0 < len(gotAnswers) {
				t.Error("DumpAnswers() = empty, want empty")
				return
			}
			if 0 < len(tt.wantAnswers) && !reflect.DeepEqual(gotAnswers, tt.wantAnswers) {
				t.Errorf("DumpAnswers() = %v, want %v", gotAnswers, tt.wantAnswers)
			}
		})
	}
}
