//go:build windows

package ports

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestWindowsSelfSockets(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1:0"
			if network[3] == '6' {
				host = "[::1]:0"
			}
			var endpoint string
			if network[:3] == "tcp" {
				ln, err := net.Listen(network, host)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				endpoint = ln.Addr().String()
			} else {
				conn, err := net.ListenPacket(network, host)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				endpoint = conn.LocalAddr().String()
			}
			protocol := network[:3]
			if network[3] == '6' {
				protocol += "6"
			}
			for attempt := 0; attempt < 10; attempt++ {
				r, err := Collect(Options{})
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range r.Sockets {
					if s.Protocol != protocol || s.Local != endpoint {
						continue
					}
					for _, p := range s.Owners {
						if p.PID == os.Getpid() {
							if p.Name == "" || p.Executable == "" || p.UID == "" || p.User == "" {
								t.Fatalf("missing self metadata: %+v", p)
							}
							t.Logf("%s %s PID=%d name=%s SID=%s user=%s", protocol, endpoint, p.PID, p.Name, p.UID, p.User)
							return
						}
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatalf("self PID %d not found for %s %s", os.Getpid(), protocol, endpoint)
		})
	}
}
