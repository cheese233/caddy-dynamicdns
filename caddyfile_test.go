// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/google/go-cmp/cmp"
)

func Test_ParseApp(t *testing.T) {
	tests := []struct {
		name    string
		d       *caddyfile.Dispenser
		want    string
		wantErr bool
	}{
		{
			name: "ip_source: upnp",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source upnp
			}`),
			want: ` {
				"ip_sources": [
					{
						"source": "upnp"
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip_source: simple http endpoints",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source simple_http http://1.com
				ip_source simple_http http://2.com
			}`),
			want: ` {
				"ip_sources": [
					{
						"source": "simple_http",
						"endpoints": ["http://1.com"]
					},
					{
						"source": "simple_http",
						"endpoints": ["http://2.com"]
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip_source: endpoints then upnp then endpoints",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source simple_http http://1.com
				ip_source upnp
				ip_source simple_http http://2.com
			}`),
			want: ` {
				"ip_sources": [
					{
						"source": "simple_http",
						"endpoints": ["http://1.com"]
					},
					{
						"source": "upnp"
					},
					{
						"source": "simple_http",
						"endpoints": ["http://2.com"]
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip_source: interface",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source interface eth0
			}`),
			want: ` {
				"ip_sources": [
					{
						"name": "eth0",
						"source": "interface"
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip versions",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				versions ipv4
			}`),
			want: ` {
				"versions": {
					"ipv4": true,
					"ipv6": false
				}
			}`,
		},
		{
			name: "ip versions: invalid version",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				versions ipv5
			}`),
			wantErr: true,
		},
		{
			name: "domains: zones get merged",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					domains {
						example @
						example test
						sub.example @
					}
				}
			`),
			want: `{
				"domains": {
					"example": [
						"@",
						"test"
					],
					"sub.example": [
						"@"
					]
				},
				"versions": {}
 			}`,
		},
		{
			name: "ip ranges",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					include "192.168.0.0/16" "2001:0db8:85a3::/48"
					exclude "192.168.10.0/24" "2001:0db8:85a3:1234::/64"
				}
			`),
			want: `{
				"include": [
					"192.168.0.0/16",
					"2001:db8:85a3::/48"
				],
				"exclude": [
					"192.168.10.0/24",
					"2001:db8:85a3:1234::/64"
				],
				"versions": {}
			}`,
		},
		{
			name: "ip ranges: include",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					include "192.168.0.0/16"
				}
			`),
			want: `{
				"include": [ "192.168.0.0/16" ],
				"versions": {}
			}`,
		},
		{
			name: "ip ranges: exclude",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					exclude "192.168.0.0/16"
				}
			`),
			want: `{
				"exclude": [ "192.168.0.0/16" ],
				"versions": {}
			}`,
		},
		{
			name: "ip ranges: invalid range",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					include "192.168.10.0/100",
					"versions": {}
				}
			`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseApp(tt.d, nil)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("parseApp() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			gotJSON := string(got.(httpcaddyfile.App).Value)
			if diff := equivalentJSON(gotJSON, tt.want, t); diff != "" {
				t.Errorf("parseApp() diff(-got +want):\n%s", diff)
			}
		})
	}
}

func equivalentJSON(s1, s2 string, t *testing.T) string {
	var v1, v2 map[string]interface{}
	if err := json.Unmarshal([]byte(s1), &v1); err != nil {
		t.Error(err)
	}
	if err := json.Unmarshal([]byte(s2), &v2); err != nil {
		t.Error(err)
	}

	return cmp.Diff(v1, v2)
}

func TestIPSettingsMatchesRejectFilter(t *testing.T) {
	tests := []struct {
		name         string
		rejectRegex  string
		ip           string
		shouldReject bool
		wantErr      bool
	}{
		{
			name:         "no regex filter",
			rejectRegex:  "",
			ip:           "192.168.1.1",
			shouldReject: false,
			wantErr:      false,
		},
		{
			name:         "match private IPv4",
			rejectRegex:  `^192\.168\..*`,
			ip:           "192.168.1.1",
			shouldReject: true,
			wantErr:      false,
		},
		{
			name:         "no match private IPv4",
			rejectRegex:  `^192\.168\..*`,
			ip:           "8.8.8.8",
			shouldReject: false,
			wantErr:      false,
		},
		{
			name:         "match loopback IPv4",
			rejectRegex:  `^127\..*`,
			ip:           "127.0.0.1",
			shouldReject: true,
			wantErr:      false,
		},
		{
			name:         "reject IPv6 loopback",
			rejectRegex:  `^::1$`,
			ip:           "::1",
			shouldReject: true,
			wantErr:      false,
		},
		{
			name:         "allow other IPv6",
			rejectRegex:  `^::1$`,
			ip:           "2001:db8::1",
			shouldReject: false,
			wantErr:      false,
		},
		{
			name:         "match all with .*",
			rejectRegex:  `.*`,
			ip:           "8.8.8.8",
			shouldReject: true,
			wantErr:      false,
		},
		{
			name:         "reject link-local IPv6",
			rejectRegex:  `^fe80:.*`,
			ip:           "fe80::1",
			shouldReject: true,
			wantErr:      false,
		},
		{
			name:         "match 10.x.x.x",
			rejectRegex:  `^10\..*`,
			ip:           "10.0.0.1",
			shouldReject: true,
			wantErr:      false,
		},
		{
			name:         "reject multicast",
			rejectRegex:  `^(224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239)\..*`,
			ip:           "224.0.0.1",
			shouldReject: true,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &IPSettings{
				RejectIPRegex: tt.rejectRegex,
			}

			ip, err := netip.ParseAddr(tt.ip)
			if err != nil {
				t.Fatalf("failed to parse IP: %v", err)
			}

			result := settings.MatchesRejectFilter(ip)
			if result != tt.shouldReject {
				t.Errorf("MatchesRejectFilter() = %v, want %v", result, tt.shouldReject)
			}
		})
	}
}

func TestIPSettingsIsIPAllowed(t *testing.T) {
	tests := []struct {
		name       string
		rejectRegex string
		ip         string
		isAllowed  bool
	}{
		{
			name:       "no filter allows all",
			rejectRegex: "",
			ip:         "192.168.1.1",
			isAllowed:  true,
		},
		{
			name:       "reject filter blocks matching IPs",
			rejectRegex: `^192\.168\..*`,
			ip:         "192.168.1.1",
			isAllowed:  false,
		},
		{
			name:       "reject filter allows non-matching IPs",
			rejectRegex: `^192\.168\..*`,
			ip:         "8.8.8.8",
			isAllowed:  true,
		},
		{
			name:       "reject localhost",
			rejectRegex: `^127\..*|^::1$`,
			ip:         "127.0.0.1",
			isAllowed:  false,
		},
		{
			name:       "allow non-localhost",
			rejectRegex: `^127\..*|^::1$`,
			ip:         "192.168.1.1",
			isAllowed:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &IPSettings{
				RejectIPRegex: tt.rejectRegex,
			}

			ip, err := netip.ParseAddr(tt.ip)
			if err != nil {
				t.Fatalf("failed to parse IP: %v", err)
			}

			result := settings.IsIPAllowed(ip)
			if result != tt.isAllowed {
				t.Errorf("IsIPAllowed() = %v, want %v", result, tt.isAllowed)
			}
		})
	}
}

func TestStaticGetIPsWithRejectFilter(t *testing.T) {
	tests := []struct {
		name         string
		staticIPs    []string
		rejectRegex  string
		expectedIPs  []string
		v4Enabled    bool
		v6Enabled    bool
	}{
		{
			name:        "no filter returns all",
			staticIPs:   []string{"192.168.1.1", "2001:db8::1"},
			rejectRegex: "",
			expectedIPs: []string{"192.168.1.1", "2001:db8::1"},
			v4Enabled:   true,
			v6Enabled:   true,
		},
		{
			name:        "reject private IPv4",
			staticIPs:   []string{"192.168.1.1", "8.8.8.8", "2001:db8::1"},
			rejectRegex: `^192\.168\..*`,
			expectedIPs: []string{"8.8.8.8", "2001:db8::1"},
			v4Enabled:   true,
			v6Enabled:   true,
		},
		{
			name:        "only IPv4 enabled",
			staticIPs:   []string{"192.168.1.1", "8.8.8.8", "2001:db8::1"},
			rejectRegex: `^192\.168\..*`,
			expectedIPs: []string{"8.8.8.8"},
			v4Enabled:   true,
			v6Enabled:   false,
		},
		{
			name:        "only IPv6 enabled",
			staticIPs:   []string{"192.168.1.1", "8.8.8.8", "2001:db8::1"},
			rejectRegex: `^192\.168\..*`,
			expectedIPs: []string{"2001:db8::1"},
			v4Enabled:   false,
			v6Enabled:   true,
		},
		{
			name:        "reject all returns empty",
			staticIPs:   []string{"192.168.1.1", "10.0.0.1"},
			rejectRegex: `^(192\.168|10\.0)\..*`,
			expectedIPs: []string{},
			v4Enabled:   true,
			v6Enabled:   true,
		},
		{
			name:        "reject loopback",
			staticIPs:   []string{"127.0.0.1", "::1", "8.8.8.8"},
			rejectRegex: `^127\..*|^::1$`,
			expectedIPs: []string{"8.8.8.8"},
			v4Enabled:   true,
			v6Enabled:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Static{}
			for _, ipStr := range tt.staticIPs {
				ip, err := netip.ParseAddr(ipStr)
				if err != nil {
					t.Fatalf("failed to parse IP: %v", err)
				}
				s.IPs = append(s.IPs, ip)
			}

			settings := &IPSettings{
				RejectIPRegex: tt.rejectRegex,
				IPVersions: IPVersions{
					IPv4: &tt.v4Enabled,
					IPv6: &tt.v6Enabled,
				},
			}

			result, err := s.GetIPs(context.Background(), settings)
			if err != nil {
				t.Fatalf("GetIPs() error = %v", err)
			}

			resultStrs := make([]string, len(result))
			for i, ip := range result {
				resultStrs[i] = ip.String()
			}

			if len(resultStrs) != len(tt.expectedIPs) {
				t.Errorf("GetIPs() returned %d IPs, want %d", len(resultStrs), len(tt.expectedIPs))
				t.Errorf("Got: %v, Want: %v", resultStrs, tt.expectedIPs)
				return
			}

			for i, ip := range resultStrs {
				if ip != tt.expectedIPs[i] {
					t.Errorf("GetIPs()[%d] = %v, want %v", i, ip, tt.expectedIPs[i])
				}
			}
		})
	}
}

func TestRejectFilterRegexCompilation(t *testing.T) {
	// Test that regex is compiled on first use and cached
	settings := &IPSettings{
		RejectIPRegex: `^192\.168\..*`,
	}

	ip, _ := netip.ParseAddr("192.168.1.1")

	// First call should compile the regex
	result1 := settings.MatchesRejectFilter(ip)
	if !result1 {
		t.Errorf("expected IP to be rejected on first call")
	}

	// Verify that the compiled pattern is cached
	if settings.rejectIPPattern == nil {
		t.Errorf("expected regex pattern to be compiled and cached")
	}

	// Second call should use the cached pattern
	result2 := settings.MatchesRejectFilter(ip)
	if result2 != result1 {
		t.Errorf("inconsistent results on repeated calls")
	}
}

func TestComplexRejectPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		testIPs map[string]bool // ip -> shouldBeRejected
	}{
		{
			name:    "reject all private ranges",
			pattern: `^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*`,
			testIPs: map[string]bool{
				"10.0.0.1":       true,
				"172.16.0.1":     true,
				"172.31.255.255": true,
				"192.168.1.1":    true,
				"8.8.8.8":        false,
				"1.1.1.1":        false,
			},
		},
		{
			name:    "reject localhost and link-local",
			pattern: `^(127\.|::1$|fe80:).*`,
			testIPs: map[string]bool{
				"127.0.0.1":      true,
				"127.0.0.255":    true,
				"::1":            true,
				"fe80::1":        true,
				"fe80::ffff":     true,
				"8.8.8.8":        false,
				"2001:db8::1":    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &IPSettings{
				RejectIPRegex: tt.pattern,
			}

			for ipStr, shouldBeRejected := range tt.testIPs {
				ip, err := netip.ParseAddr(ipStr)
				if err != nil {
					t.Fatalf("failed to parse IP %s: %v", ipStr, err)
				}

				result := settings.MatchesRejectFilter(ip)
				if result != shouldBeRejected {
					t.Errorf("IP %s: got rejected=%v, want %v", ipStr, result, shouldBeRejected)
				}
			}
		})
	}
}
