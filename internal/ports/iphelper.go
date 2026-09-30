package ports

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
)

// IP Helper OWNER_PID layouts, supplied by the Windows test unit's real API
// probes. Count is at 0; rows start at 4. Returned buffer slack is NOT row padding.
// Keep this byte parser platform independent so malformed tables can be tested
// on every build host without unsafe struct casts or host alignment assumptions.
func parseIPHelper(b []byte, protocol string, all bool) ([]Socket, error) {
	stride := map[string]int{"tcp": 24, "tcp6": 56, "udp": 12, "udp6": 28}[protocol]
	if stride == 0 || len(b) < 4 {
		return nil, fmt.Errorf("invalid IP Helper table %q", protocol)
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	if count > uint64((len(b)-4)/stride) {
		return nil, fmt.Errorf("truncated %s table: count %d exceeds buffer", protocol, count)
	}
	out := []Socket{}
	for i := 0; i < int(count); i++ {
		r := b[4+i*stride : 4+(i+1)*stride]
		s := Socket{Protocol: protocol, State: "BOUND", Owners: []Process{}}
		var pid, state uint32
		switch protocol {
		case "tcp":
			state = binary.LittleEndian.Uint32(r)
			s.Local = ipHelperEndpoint(r[4:8], r[8:10], 0)
			s.Remote = ipHelperEndpoint(r[12:16], r[16:18], 0)
			pid = binary.LittleEndian.Uint32(r[20:24])
		case "tcp6":
			s.Local = ipHelperEndpoint(r[:16], r[20:22], binary.LittleEndian.Uint32(r[16:20]))
			s.Remote = ipHelperEndpoint(r[24:40], r[44:46], binary.LittleEndian.Uint32(r[40:44]))
			state = binary.LittleEndian.Uint32(r[48:52])
			pid = binary.LittleEndian.Uint32(r[52:56])
		case "udp":
			s.Local = ipHelperEndpoint(r[:4], r[4:6], 0)
			pid = binary.LittleEndian.Uint32(r[8:12])
		case "udp6":
			s.Local = ipHelperEndpoint(r[:16], r[20:22], binary.LittleEndian.Uint32(r[16:20]))
			pid = binary.LittleEndian.Uint32(r[24:28])
		}
		if protocol == "tcp" || protocol == "tcp6" {
			if !all && state != 2 {
				continue
			}
			s.State = ipHelperTCPState(state)
		}
		// PID 0 represents unknown/kernel ownership, not a real process owner.
		if pid != 0 {
			s.Owners = append(s.Owners, Process{PID: int(pid)})
		}
		out = append(out, s)
	}
	return out, nil
}

func ipHelperEndpoint(addr, port []byte, scope uint32) string {
	a, _ := netip.AddrFromSlice(addr)
	if a.Is6() && scope != 0 {
		a = a.WithZone(strconv.FormatUint(uint64(scope), 10))
	}
	return netip.AddrPortFrom(a, binary.BigEndian.Uint16(port)).String()
}

func ipHelperTCPState(state uint32) string {
	names := [...]string{"", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"}
	if state > 0 && state < uint32(len(names)) {
		return names[state]
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}
