//go:build windows

package ports

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")

func Collect(opts Options) (Result, error) {
	r := Result{Sockets: []Socket{}, Devices: []Device{}, Warnings: []string{}, Scope: "Windows IP Helper OWNER_PID tables; best-effort process token SID/user and image path; non-atomic snapshot (PID reuse possible); UDP peer unavailable"}
	if opts.Devices {
		r.Warnings = append(r.Warnings, "--devices is supported only on Linux")
	}
	readable := 0
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		name, class := "GetExtendedTcpTable", uintptr(5) // TCP_TABLE_OWNER_PID_ALL
		if protocol == "udp" || protocol == "udp6" {
			name, class = "GetExtendedUdpTable", 1 // UDP_TABLE_OWNER_PID
		}
		af := uintptr(windows.AF_INET)
		if protocol == "tcp6" || protocol == "udp6" {
			af = windows.AF_INET6
		}
		b, err := readIPHelper(ipHelper.NewProc(name), af, class)
		var sockets []Socket
		if err == nil {
			sockets, err = parseIPHelper(b, protocol, opts.All)
		}
		if err != nil {
			r.Warnings = append(r.Warnings, protocol+": "+err.Error())
			continue
		}
		readable++
		r.Sockets = append(r.Sockets, sockets...)
	}
	if readable == 0 {
		return r, fmt.Errorf("no Windows IP Helper tables could be read: %v", r.Warnings)
	}
	cache := make(map[int]Process)
	missing, unknown := 0, 0
	for i := range r.Sockets {
		if len(r.Sockets[i].Owners) == 0 {
			unknown++
			continue
		}
		pid := r.Sockets[i].Owners[0].PID
		p, ok := cache[pid]
		if !ok {
			p = windowsProcess(uint32(pid))
			cache[pid] = p
			if p.Executable == "" || p.UID == "" || p.User == "" {
				missing++
			}
		}
		r.Sockets[i].Owners[0] = p
	}
	if missing > 0 || unknown > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d process descriptions incomplete; %d sockets without a PID (access denied, protected/kernel process or exit)", missing, unknown))
	}
	sort.SliceStable(r.Sockets, func(i, j int) bool {
		a, b := r.Sockets[i], r.Sockets[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Local != b.Local {
			return a.Local < b.Local
		}
		return a.Remote < b.Remote
	})
	return r, nil
}

func readIPHelper(proc *windows.LazyProc, af, class uintptr) ([]byte, error) {
	if err := proc.Find(); err != nil {
		return nil, err
	}
	var size uint32
	var b []byte
	for attempt := 0; attempt < 5; attempt++ {
		var ptr unsafe.Pointer
		if len(b) > 0 {
			ptr = unsafe.Pointer(&b[0])
		}
		rc, _, _ := proc.Call(uintptr(ptr), uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		runtime.KeepAlive(b)
		if rc == 0 {
			if size < 4 || uint64(size) > uint64(len(b)) {
				return nil, fmt.Errorf("invalid returned table size %d", size)
			}
			return b[:size], nil
		}
		if windows.Errno(rc) != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, windows.Errno(rc)
		}
		if size < 4 || size > 64<<20 {
			return nil, fmt.Errorf("invalid requested table size %d", size)
		}
		b = make([]byte, size)
	}
	return nil, fmt.Errorf("IP Helper table changed during 5 attempts")
}

func windowsProcess(pid uint32) Process {
	p := Process{PID: int(pid)}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return p
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil && n <= uint32(len(buf)) {
		p.Executable = windows.UTF16ToString(buf[:n])
		p.Name = filepath.Base(p.Executable)
	}
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) == nil {
		defer token.Close()
		if user, err := token.GetTokenUser(); err == nil {
			p.UID = user.User.Sid.String()
			if account, domain, _, err := user.User.Sid.LookupAccount(""); err == nil {
				p.User = account
				if domain != "" {
					p.User = domain + "\\" + account
				}
			}
		}
	}
	return p
}
