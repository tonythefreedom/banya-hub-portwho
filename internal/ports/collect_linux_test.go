//go:build linux

package ports

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every fixture is synthetic; native-endian encoding supports big-endian Linux.
func procAddress(ip string, port uint16) string {
	b := netip.MustParseAddr(ip).AsSlice()
	for i := 0; i < len(b); i += 4 {
		v := binary.NativeEndian.Uint32(b[i : i+4])
		binary.BigEndian.PutUint32(b[i:i+4], v)
	}
	return strings.ToUpper(hex.EncodeToString(b)) + fmt.Sprintf(":%04X", port)
}

func row(local, remote, state, uid, inode string) string {
	z := strings.Repeat("0", 8)
	return fmt.Sprintf(" 0: %s %s %s %s:%s 00:%s %s %s 0 %s 1 %s 100 0 0 10 0\n", local, remote, state, z, z, z, z, uid, inode, z+z)
}

func TestEndpoints(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "1.2.3.4", "::1", "2001:db8:102:304:506:708:90a:b0c", "::ffff:192.0.2.1"} {
		want := netip.AddrPortFrom(netip.MustParseAddr(ip), 65535).String()
		got, err := parseEndpoint(procAddress(ip, 65535), strings.Contains(ip, ":"))
		if err != nil || got != want {
			t.Fatalf("%s: %q %v want %q", ip, got, err, want)
		}
	}
	for _, s := range []string{"", "0100007F:10000", "0100007G:0001", "0100007F:-001", "0100007F:1", "::"} {
		if _, err := parseEndpoint(s, false); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	v4, v6 := "04030201:1234", "B80D012004030201080706050C0B0A09:1234"
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		v4, v6 = "01020304:1234", "20010DB80102030405060708090A0B0C:1234"
	}
	for input, want := range map[string]string{v4: "1.2.3.4:4660", v6: "[2001:db8:102:304:506:708:90a:b0c]:4660"} {
		got, err := parseEndpoint(input, len(input) > 13)
		if err != nil || got != want {
			t.Fatal(got, err, want)
		}
	}
}

func TestParseTable(t *testing.T) {
	local, remote := procAddress("127.0.0.1", 8080), procAddress("0.0.0.0", 0)
	input := " sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		row(local, remote, "0A", "1000", "18446744073709551615") +
		row(local, remote, "01", "0", "2") + row(local, remote, "0A", "1001", "3") +
		row(local, remote, "0A", "0", "0") + "short malformed\n" + row(local, remote, "ZZ", "1000", "4") +
		row(local, remote, "0A", "bad", "4") + row(local, remote, "0A", "0", "-1")
	s, bad, err := parseTable(strings.NewReader(input), "tcp", false)
	if err != nil || bad != 4 || len(s) != 3 {
		t.Fatalf("%+v %d %v", s, bad, err)
	}
	if s[0].UID != "1000" || s[0].Inode != ^uint64(0) || s[0].State != "LISTEN" {
		t.Fatal(s[0])
	}
	all, _, _ := parseTable(strings.NewReader(input), "tcp", true)
	if len(all) != 4 {
		t.Fatal(all)
	}
	udp, _, _ := parseTable(strings.NewReader(row(local, remote, "07", "0", "1")+row(local, remote, "01", "0", "2")), "udp", false)
	if len(udp) != 2 || udp[0].State != "BOUND" || udp[1].State != "CONNECTED" {
		t.Fatal(udp)
	}
	for _, state := range []uint8{10, 255} {
		if got := stateName(state, true); got != fmt.Sprintf("UNKNOWN(0x%02X)", state) {
			t.Fatal(got)
		}
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestPartialTable(t *testing.T) {
	input := row(procAddress("127.0.0.1", 1), procAddress("0.0.0.0", 0), "0A", "0", "1")
	s, _, err := parseTable(io.MultiReader(strings.NewReader(input), errorReader{}), "tcp", false)
	if len(s) != 1 || err == nil {
		t.Fatal(s, err)
	}
}

func writeFixture(t *testing.T, root, path, text string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func linkFixture(t *testing.T, root, path, target string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"tcp", "tcp6", "udp", "udp6"} {
		writeFixture(t, root, "net/"+p, "sl local_address rem_address st\n")
	}
	writeFixture(t, root, "passwd", "alice:x:1001:1001::/:/bin/false\n")
	return root
}

func statFixture(t *testing.T, root, pid, start string) {
	t.Helper()
	writeFixture(t, root, pid+"/stat", pid+" (name ) with spaces) S "+strings.Repeat("0 ", 18)+start+" 0\n")
}

type fixtureInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (f fixtureInfo) Mode() os.FileMode { return f.mode }

func deviceStat(string) (os.FileInfo, error) {
	return fixtureInfo{mode: os.ModeDevice | os.ModeCharDevice}, nil
}

func warningContains(r Result, text string) bool {
	return strings.Contains(strings.Join(r.Warnings, "\n"), text)
}

func TestCollectFixture(t *testing.T) {
	root := fixture(t)
	l, r := procAddress("127.0.0.1", 8080), procAddress("0.0.0.0", 0)
	writeFixture(t, root, "net/tcp", row(l, r, "0A", "1000", "123")+row(l, r, "0A", "0", "124")+row(l, r, "0A", "0", "0"))
	for _, pid := range []string{"12", "34"} {
		statFixture(t, root, pid, "1234")
		writeFixture(t, root, pid+"/comm", "worker (one)\n")
		writeFixture(t, root, pid+"/status", "Name:\tworker\nUid:\t1001\t1002\t1002\t1002\n")
		writeFixture(t, root, pid+"/cgroup", "0::/system.slice/docker-abc.scope\n")
		linkFixture(t, root, pid+"/exe", "/app/worker (deleted)")
		linkFixture(t, root, pid+"/fd/3", "socket:[123]")
		linkFixture(t, root, pid+"/fd/4", "socket:[123]")
		linkFixture(t, root, pid+"/fd/5", "/dev/nvidia0")
		linkFixture(t, root, pid+"/fd/6", "/dev/dxg")
		linkFixture(t, root, pid+"/fd/7", "/dev/not-nvidia")
	}
	writeFixture(t, root, "56/comm", "gone\n")
	got, err := collectLinuxWithStat(root, filepath.Join(root, "passwd"), Options{Devices: true}, deviceStat)
	if err != nil || len(got.Sockets) != 3 || len(got.Devices) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	var shared Socket
	for _, s := range got.Sockets {
		if s.Inode == 123 {
			shared = s
		} else if len(s.Owners) != 0 {
			t.Fatal(s)
		}
	}
	if len(shared.Owners) != 2 || shared.Owners[0].PID != 12 || shared.Owners[1].PID != 34 {
		t.Fatal(shared)
	}
	p := shared.Owners[0]
	if shared.UID != "1000" || p.UID != "1001" || p.User != "alice" || p.Name != "worker (one)" || p.Executable != "/app/worker (deleted)" || p.Container != "docker (cgroup heuristic)" {
		t.Fatal(shared)
	}
	if !warningContains(got, "process inventories") || !warningContains(got, "unknown owners") {
		t.Fatal(got.Warnings)
	}
	for _, d := range got.Devices {
		if len(d.Owners) != 2 {
			t.Fatal(d)
		}
	}
	without, err := collectLinux(root, filepath.Join(root, "absent-passwd"), Options{})
	if err != nil || len(without.Devices) != 0 || !warningContains(without, "user names") {
		t.Fatal(without, err)
	}
	for _, s := range without.Sockets {
		for _, p := range s.Owners {
			if p.User != "" || p.UID != "1001" {
				t.Fatal(p)
			}
		}
	}
}

func TestDeviceKindsAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		err   error
		start string
		want  int
	}{
		{"character", os.ModeDevice | os.ModeCharDevice, nil, "1234", 1},
		{"regular", 0, nil, "1234", 0},
		{"directory", os.ModeDir, nil, "1234", 0},
		{"block", os.ModeDevice, nil, "1234", 0},
		{"denied", 0, os.ErrPermission, "1234", 0},
		{"gone", 0, os.ErrNotExist, "1234", 0},
		{"reused", os.ModeDevice | os.ModeCharDevice, nil, "5678", 0},
		{"unverifiable", os.ModeDevice | os.ModeCharDevice, nil, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixture(t)
			statFixture(t, root, "12", "1234")
			linkFixture(t, root, "12/fd/3", "/dev/nvidia0")
			stat := func(string) (os.FileInfo, error) {
				if tc.start == "" {
					if err := os.Remove(filepath.Join(root, "12/stat")); err != nil {
						t.Fatal(err)
					}
				} else {
					statFixture(t, root, "12", tc.start)
				}
				return fixtureInfo{mode: tc.mode}, tc.err
			}
			r, err := collectLinuxWithStat(root, filepath.Join(root, "passwd"), Options{Devices: true}, stat)
			if err != nil || len(r.Devices) != tc.want {
				t.Fatal(r, err)
			}
			if tc.err != nil && !warningContains(r, "fd lookup/stat") {
				t.Fatal(r.Warnings)
			}
			if tc.start != "1234" && !warningContains(r, "identity unverifiable") {
				t.Fatal(r.Warnings)
			}
			if tc.want == 1 && !warningContains(r, "unavailable metadata") {
				t.Fatal(r.Warnings)
			}
		})
	}
	for _, pair := range [][2]string{{"", ""}, {"", "1"}, {"1", ""}, {"1", "2"}} {
		if sameProcess(pair[0], pair[1]) {
			t.Fatal(pair)
		}
	}
}

func TestMissingTablesAndMetadata(t *testing.T) {
	if _, err := collectLinux(t.TempDir(), "absent", Options{}); err == nil {
		t.Fatal("expected error")
	}
	root := fixture(t)
	if err := os.Remove(filepath.Join(root, "net/tcp6")); err != nil {
		t.Fatal(err)
	}
	got, err := collectLinux(root, filepath.Join(root, "passwd"), Options{})
	if err != nil || !warningContains(got, "tcp6:") {
		t.Fatal(got, err)
	}
	p, missing := readProcess(root, 99, nil)
	if !missing || p.PID != 99 || p.UID != "" || p.Name != "" {
		t.Fatal(p)
	}
	for _, s := range []string{"0::/\n", "2:cpu:/user.slice\n", "0::/mydocker-backup\n", "invalid"} {
		if containerHint(s) != "" {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"0::/kubepods/burstable/pod-abc\n", "3:cpu:/docker/abc\n", "0::/libpod-abc.scope\n"} {
		if containerHint(s) == "" {
			t.Fatal(s)
		}
	}
	statFixture(t, root, "99", "1234")
	if processStart(filepath.Join(root, "99")) != "1234" {
		t.Fatal("starttime parse")
	}
}

func TestJSONArrays(t *testing.T) {
	root := fixture(t)
	r, err := collectLinux(root, filepath.Join(root, "passwd"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), "null") {
		t.Fatal(string(b), err)
	}
	writeFixture(t, root, "net/tcp", row(procAddress("127.0.0.1", 1), procAddress("0.0.0.0", 0), "0A", "0", "123"))
	r, err = collectLinux(root, filepath.Join(root, "passwd"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"owners":[]`) {
		t.Fatal(string(b), err)
	}
}

func TestPermissionDeniedFD(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses fixture permissions")
	}
	root := fixture(t)
	writeFixture(t, root, "123/fd/unused", "")
	fd := filepath.Join(root, "123/fd")
	if err := os.Chmod(fd, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fd, 0700) })
	r, err := collectLinux(root, filepath.Join(root, "passwd"), Options{})
	if err != nil || !warningContains(r, "process inventories") {
		t.Fatal(r, err)
	}
}

func TestSelfSockets(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if strings.HasSuffix(network, "6") {
				addr = "[::1]:0"
			}
			var local string
			if strings.HasPrefix(network, "tcp") {
				l, err := net.Listen(network, addr)
				if err != nil {
					if strings.HasSuffix(network, "6") {
						t.Skip(err)
					}
					t.Fatal(err)
				}
				defer l.Close()
				local = l.Addr().String()
			} else {
				l, err := net.ListenPacket(network, addr)
				if err != nil {
					if strings.HasSuffix(network, "6") {
						t.Skip(err)
					}
					t.Fatal(err)
				}
				defer l.Close()
				local = l.LocalAddr().String()
			}
			r, err := Collect(Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range r.Sockets {
				if s.Local != local || s.Protocol != strings.TrimSuffix(network, "4") {
					continue
				}
				for _, p := range s.Owners {
					if p.PID == os.Getpid() {
						if p.Name == "" || p.Executable == "" || p.UID != strconv.Itoa(os.Getuid()) {
							t.Fatal(p)
						}
						return
					}
				}
			}
			t.Fatalf("self socket %s %s not found", network, local)
		})
	}
}

func TestDeviceSelf(t *testing.T) {
	if os.Getenv("PORTWHO_TEST_DEVICES") != "1" {
		t.Skip("set PORTWHO_TEST_DEVICES=1 for real device read-only open test")
	}
	paths, _ := filepath.Glob("/dev/nvidia*")
	paths = append(paths, "/dev/dxg")
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			t.Logf("cannot open %s: %v", path, err)
			continue
		}
		defer f.Close()
		r, err := Collect(Options{Devices: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range r.Devices {
			if d.Path == path {
				for _, p := range d.Owners {
					if p.PID == os.Getpid() {
						t.Logf("verified real device %s owner PID %d name=%s", path, p.PID, p.Name)
						return
					}
				}
			}
		}
		t.Fatalf("open device %s missing self owner", path)
	}
	t.Skip("no readable NVIDIA/dxg character device; actual holder verification unavailable")
}

func FuzzProcTable(f *testing.F) {
	f.Add("sl local_address rem_address st\n"+row(procAddress("127.0.0.1", 80), procAddress("0.0.0.0", 0), "0A", "1000", "123"), false)
	f.Add(row(procAddress("::1", 53), procAddress("::", 0), "07", "0", "456"), true)
	f.Add("bad\n", false)
	f.Fuzz(func(t *testing.T, input string, ipv6 bool) {
		protocol := "tcp"
		if ipv6 {
			protocol = "udp6"
		}
		sockets, _, _ := parseTable(strings.NewReader(input), protocol, true)
		for _, s := range sockets {
			if _, err := netip.ParseAddrPort(s.Local); err != nil {
				t.Fatal(err)
			}
			if _, err := netip.ParseAddrPort(s.Remote); err != nil {
				t.Fatal(err)
			}
		}
	})
}
