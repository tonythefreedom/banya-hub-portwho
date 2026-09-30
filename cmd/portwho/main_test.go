package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/tonythefreedom/banya-hub-portwho/internal/ports"
)

func TestCLI(t *testing.T) {
	var out, stderr bytes.Buffer
	collect := func(o ports.Options) (ports.Result, error) {
		if !o.All || !o.Devices {
			t.Error("flags not passed")
		}
		return ports.Result{Sockets: []ports.Socket{}, Devices: []ports.Device{}, Warnings: []string{"partial"}, Scope: "test"}, nil
	}
	if code := run([]string{"--all", "--devices", "--json"}, &out, &stderr, collect); code != 0 {
		t.Fatal(code, stderr.String())
	}
	var r ports.Result
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 1 || r.Scope != "test" {
		t.Fatal(r)
	}
	for _, args := range [][]string{{"--bad"}, {"unexpected"}} {
		if code := run(args, &out, &stderr, collect); code != 2 {
			t.Fatal(code)
		}
	}
	if code := run([]string{"--help"}, &out, &stderr, collect); code != 0 {
		t.Fatal(code)
	}
	if code := run(nil, &out, &stderr, func(ports.Options) (ports.Result, error) { return ports.Result{}, errors.New("unavailable") }); code != 1 {
		t.Fatal(code)
	}
}

func TestTableUnknownAndEscaping(t *testing.T) {
	var out bytes.Buffer
	r := ports.Result{Sockets: []ports.Socket{{Protocol: "tcp", Local: "127.0.0.1:1", State: "LISTEN"}, {Protocol: "udp", Owners: []ports.Process{{PID: 42, Name: "bad\n\x1bname\u202e", UID: "0"}}}}}
	if err := render(&out, r, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\u202e") || strings.Contains(out.String(), "bad\n") {
		t.Fatal("unescaped output")
	}
	if !strings.Contains(out.String(), "?") || !strings.Contains(out.String(), "42") {
		t.Fatal(out.String())
	}
}

type failOnceWriter struct{ failed bool }

func (w *failOnceWriter) Write(p []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return 0, errors.New("output unavailable")
	}
	return len(p), nil
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return 0, nil }

func TestOutputErrors(t *testing.T) {
	collect := func(ports.Options) (ports.Result, error) {
		return ports.Result{Sockets: []ports.Socket{{Protocol: "tcp"}}, Devices: []ports.Device{{Path: "/dev/nvidia0", Owners: []ports.Process{{PID: 1}}}}}, nil
	}
	for _, args := range [][]string{{"--json"}, {}, {"--devices"}} {
		for _, out := range []io.Writer{&failOnceWriter{}, shortWriter{}} {
			if code := run(args, out, io.Discard, collect); code != 1 {
				t.Fatalf("%v: exit %d", args, code)
			}
		}
	}
}
