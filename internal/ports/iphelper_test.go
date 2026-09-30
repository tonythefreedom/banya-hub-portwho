package ports

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestIPHelperLayouts(t *testing.T) {
	for _, tc := range []struct {
		protocol                     string
		size, addr, port, pid, state int
		local                        string
	}{
		{"tcp", 24, 4, 8, 20, 0, "127.0.0.1:4660"},
		{"tcp6", 56, 0, 20, 52, 48, "[::1%7]:4660"},
		{"udp", 12, 0, 4, 8, -1, "127.0.0.1:4660"},
		{"udp6", 28, 0, 20, 24, -1, "[::1%7]:4660"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			b := make([]byte, 4+tc.size+8) // observed API slack, not another row
			binary.LittleEndian.PutUint32(b, 1)
			r := b[4:]
			addr := netip.MustParseAddr("127.0.0.1")
			if tc.size == 56 || tc.size == 28 {
				addr = netip.MustParseAddr("::1")
				binary.LittleEndian.PutUint32(r[16:], 7)
			}
			copy(r[tc.addr:], addr.AsSlice())
			binary.BigEndian.PutUint16(r[tc.port:], 4660)
			binary.LittleEndian.PutUint32(r[tc.pid:], 321)
			if tc.state >= 0 {
				binary.LittleEndian.PutUint32(r[tc.state:], 2)
			}
			remote := ""
			if tc.protocol == "tcp" {
				copy(r[12:16], netip.MustParseAddr("192.0.2.7").AsSlice())
				binary.BigEndian.PutUint16(r[16:18], 54321)
				remote = "192.0.2.7:54321"
			}
			if tc.protocol == "tcp6" {
				copy(r[24:40], netip.MustParseAddr("fe80::abcd").AsSlice())
				binary.LittleEndian.PutUint32(r[40:44], 9)
				binary.BigEndian.PutUint16(r[44:46], 54321)
				remote = "[fe80::abcd%9]:54321"
			}
			s, err := parseIPHelper(b, tc.protocol, false)
			if err != nil || len(s) != 1 {
				t.Fatalf("%v %v", s, err)
			}
			state := "BOUND"
			if tc.state >= 0 {
				state = "LISTEN"
			}
			if s[0].Remote != remote || s[0].State != state {
				t.Fatalf("remote/state: %+v", s[0])
			}
			if s[0].Local != tc.local || len(s[0].Owners) != 1 || s[0].Owners[0].PID != 321 {
				t.Fatalf("wrong row: %+v", s[0])
			}
			if tc.state >= 0 {
				binary.LittleEndian.PutUint32(r[tc.state:], 5)
				s, err = parseIPHelper(b, tc.protocol, false)
				if err != nil || len(s) != 0 {
					t.Fatal("non-listener not filtered")
				}
				s, err = parseIPHelper(b, tc.protocol, true)
				if err != nil || len(s) != 1 || s[0].State != "ESTABLISHED" {
					t.Fatal("all filter")
				}
			}
			binary.LittleEndian.PutUint32(r[tc.pid:], 0)
			s, err = parseIPHelper(b, tc.protocol, true)
			if err != nil || len(s) != 1 || len(s[0].Owners) != 0 {
				t.Fatal("PID zero is not unknown")
			}
			multi := make([]byte, 4+2*tc.size)
			binary.LittleEndian.PutUint32(multi, 2)
			copy(multi[4:], r[:tc.size])
			copy(multi[4+tc.size:], r[:tc.size])
			binary.LittleEndian.PutUint32(multi[4+tc.size+tc.pid:], 654)
			s, err = parseIPHelper(multi, tc.protocol, true)
			if err != nil || len(s) != 2 || len(s[1].Owners) != 1 || s[1].Owners[0].PID != 654 {
				t.Fatal("multiple rows", s, err)
			}
			if _, err := parseIPHelper(b[:4+tc.size-1], tc.protocol, true); err == nil {
				t.Fatal("truncation accepted")
			}
			binary.LittleEndian.PutUint32(b, ^uint32(0))
			if _, err := parseIPHelper(b, tc.protocol, true); err == nil {
				t.Fatal("overflow count accepted")
			}
		})
	}
	if s, err := parseIPHelper(make([]byte, 4), "tcp", false); err != nil || len(s) != 0 {
		t.Fatal("empty table", s, err)
	}
	if _, err := parseIPHelper(nil, "tcp", false); err == nil {
		t.Fatal("empty header")
	}
	if _, err := parseIPHelper(make([]byte, 4), "invalid", false); err == nil {
		t.Fatal("bad protocol")
	}
	if ipHelperTCPState(99) != "UNKNOWN(99)" {
		t.Fatal("unknown state")
	}
}

func FuzzIPHelper(f *testing.F) {
	f.Add(make([]byte, 4))
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range []string{"tcp", "tcp6", "udp", "udp6"} {
			_, _ = parseIPHelper(b, p, true)
		}
	})
}
