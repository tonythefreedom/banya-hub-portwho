//go:build linux

package ports

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func Collect(opts Options) (Result, error) {
	return collectLinux("/proc", "/etc/passwd", opts)
}

func collectLinux(root, passwd string, opts Options) (Result, error) {
	return collectLinuxWithStat(root, passwd, opts, os.Stat)
}

// statFD is injectable so device fixtures need no real devices or mknod.
func collectLinuxWithStat(root, passwd string, opts Options, statFD func(string) (os.FileInfo, error)) (Result, error) {
	r := Result{Sockets: []Socket{}, Devices: []Device{}, Warnings: []string{}, Scope: "Linux /proc/net: current network namespace; visible /proc processes; best-effort owners (see warnings); non-atomic snapshot"}
	readable := 0
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open(filepath.Join(root, "net", protocol))
		if err != nil {
			r.Warnings = append(r.Warnings, protocol+": "+err.Error())
			continue
		}
		sockets, malformed, err := parseTable(f, protocol, opts.All)
		f.Close()
		readable++
		r.Sockets = append(r.Sockets, sockets...)
		if malformed > 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: skipped %d malformed rows", protocol, malformed))
		}
		if err != nil {
			r.Warnings = append(r.Warnings, protocol+": "+err.Error())
		}
	}
	if readable == 0 {
		return r, errors.New("no /proc network tables could be read")
	}
	users, err := readUsers(passwd)
	if err != nil {
		r.Warnings = append(r.Warnings, "user names: "+err.Error())
	}
	byInode := make(map[uint64][]Process)
	wanted := make(map[uint64]bool)
	for _, s := range r.Sockets {
		if s.Inode != 0 {
			wanted[s.Inode] = true
		}
	}
	byDevice := make(map[string][]Process)
	entries, err := os.ReadDir(root)
	if err != nil {
		r.Warnings = append(r.Warnings, "process inventory: "+err.Error())
	}
	unreadable, metadataMissing := 0, 0
	fdDenied, fdChanged := 0, 0
	recordFD := func(err error) {
		if os.IsPermission(err) {
			fdDenied++
		} else {
			fdChanged++
		}
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		before := processStart(dir)
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			unreadable++
			continue
		}
		inodes := make(map[uint64]bool)
		devices := make(map[string]bool)
		for _, fd := range fds {
			fdPath := filepath.Join(dir, "fd", fd.Name())
			target, err := os.Readlink(fdPath)
			if err != nil {
				recordFD(err)
				continue
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inode, err := strconv.ParseUint(target[8:len(target)-1], 10, 64)
				if err == nil && wanted[inode] {
					inodes[inode] = true
				}
			}
			if opts.Devices && isDevice(target) {
				info, err := statFD(fdPath)
				if err != nil {
					recordFD(err)
				} else if info.Mode()&os.ModeCharDevice != 0 {
					devices[target] = true
				}
			}
		}
		if len(inodes) == 0 && len(devices) == 0 {
			continue
		}
		p, missing := readProcess(dir, pid, users)
		after := processStart(dir)
		if !sameProcess(before, after) {
			unreadable++
			continue
		}
		if missing {
			metadataMissing++
		}
		for inode := range inodes {
			byInode[inode] = append(byInode[inode], p)
		}
		for device := range devices {
			byDevice[device] = append(byDevice[device], p)
		}
	}
	if unreadable > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d process inventories inaccessible, changed or identity unverifiable; owners may be unknown/incomplete", unreadable))
	}
	if metadataMissing > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d owner descriptions have unavailable metadata", metadataMissing))
	}
	if fdDenied > 0 || fdChanged > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("fd lookup/stat: %d access denied, %d vanished or unreadable; owners may be incomplete", fdDenied, fdChanged))
	}
	unknown := 0
	for i := range r.Sockets {
		owners := byInode[r.Sockets[i].Inode]
		sort.Slice(owners, func(i, j int) bool { return owners[i].PID < owners[j].PID })
		if owners == nil {
			owners = []Process{}
			unknown++
		}
		r.Sockets[i].Owners = owners
	}
	if unknown > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d sockets have unknown owners (permissions, exit, kernel sockets or namespace boundaries)", unknown))
	}
	for path, owners := range byDevice {
		sort.Slice(owners, func(i, j int) bool { return owners[i].PID < owners[j].PID })
		r.Devices = append(r.Devices, Device{Path: path, Owners: owners})
	}
	sort.Slice(r.Devices, func(i, j int) bool { return r.Devices[i].Path < r.Devices[j].Path })
	sort.Slice(r.Sockets, func(i, j int) bool {
		a, b := r.Sockets[i], r.Sockets[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Local != b.Local {
			return a.Local < b.Local
		}
		if a.Remote != b.Remote {
			return a.Remote < b.Remote
		}
		return a.Inode < b.Inode
	})
	return r, nil
}

// Linux procfs renders each 32-bit address word in native byte order, including
// IPv6. UID/inode positions refer to data rows, not the misleading header.
func parseEndpoint(s string, ipv6 bool) (string, error) {
	parts := strings.Split(s, ":")
	width := 8
	if ipv6 {
		width = 32
	}
	if len(parts) != 2 || len(parts[0]) != width || len(parts[1]) != 4 {
		return "", errors.New("invalid endpoint width")
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", err
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	for i := 0; i < len(b); i += 4 {
		v := binary.BigEndian.Uint32(b[i : i+4])
		binary.NativeEndian.PutUint32(b[i:i+4], v)
	}
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return "", errors.New("invalid address")
	}
	return netip.AddrPortFrom(addr, uint16(port)).String(), nil
}

func parseTable(r io.Reader, protocol string, all bool) ([]Socket, int, error) {
	out := []Socket{}
	bad := 0
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] == "sl" {
			continue
		}
		if len(fields) < 10 {
			bad++
			continue
		}
		local, e1 := parseEndpoint(fields[1], strings.HasSuffix(protocol, "6"))
		remote, e2 := parseEndpoint(fields[2], strings.HasSuffix(protocol, "6"))
		state, e3 := strconv.ParseUint(fields[3], 16, 8)
		uid, e4 := strconv.ParseUint(fields[7], 10, 32)
		inode, e5 := strconv.ParseUint(fields[9], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
			bad++
			continue
		}
		udp := strings.HasPrefix(protocol, "udp")
		if !all && !udp && state != 10 {
			continue
		}
		name := stateName(uint8(state), udp)
		out = append(out, Socket{Protocol: protocol, Local: local, Remote: remote, State: name, UID: strconv.FormatUint(uid, 10), Inode: inode, Owners: []Process{}})
	}
	return out, bad, scanner.Err()
}

func stateName(state uint8, udp bool) string {
	if udp {
		switch state {
		case 7:
			return "BOUND"
		case 1:
			return "CONNECTED"
		default:
			return fmt.Sprintf("UNKNOWN(0x%02X)", state)
		}
	}
	names := map[uint8]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"}
	if name, ok := names[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%02X)", state)
}

func readUsers(path string) (map[string]string, error) {
	users := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return users, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		f := strings.Split(scanner.Text(), ":")
		if len(f) >= 3 && f[0] != "" {
			users[f[2]] = f[0]
		}
	}
	return users, scanner.Err()
}

func readProcess(dir string, pid int, users map[string]string) (Process, bool) {
	p := Process{PID: pid}
	missing := false
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		p.Name = strings.TrimSuffix(string(b), "\n")
	} else {
		missing = true
	}
	var err error
	p.Executable, err = os.Readlink(filepath.Join(dir, "exe"))
	missing = missing || err != nil
	if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "Uid:" {
				if _, err := strconv.ParseUint(f[1], 10, 32); err == nil {
					p.UID = f[1]
					p.User = users[p.UID]
				}
				break
			}
		}
	}
	missing = missing || p.UID == ""
	if b, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		p.Container = containerHint(string(b))
	} else {
		missing = true
	}
	return p, missing
}

func containerHint(cgroup string) string {
	// Label recognizable components only. Root and no marker remain unknown.
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, component := range strings.Split(parts[2], "/") {
			for _, marker := range []string{"kubepods", "docker", "libpod", "containerd", "cri-containerd", "crio", "lxc"} {
				if component == marker || strings.HasPrefix(component, marker+"-") || strings.HasPrefix(component, marker+".") {
					return marker + " (cgroup heuristic)"
				}
			}
		}
	}
	return ""
}

func processStart(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ""
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return ""
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return ""
	}
	if _, err := strconv.ParseUint(f[19], 10, 64); err != nil {
		return ""
	}
	return f[19] // field 22, after pid and parenthesized comm
}

func sameProcess(before, after string) bool {
	return before != "" && before == after
}

func isDevice(path string) bool {
	return path == "/dev/dxg" || strings.HasPrefix(path, "/dev/nvidia")
}
