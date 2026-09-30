package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/tonythefreedom/banya-hub-portwho/internal/ports"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, ports.Collect)) }

func run(args []string, out, stderr io.Writer, collect func(ports.Options) (ports.Result, error)) int {
	flags := flag.NewFlagSet("portwho", flag.ContinueOnError)
	flags.SetOutput(stderr)
	all := flags.Bool("all", false, "include non-listening TCP sockets")
	devices := flags.Bool("devices", false, "include Linux /dev/nvidia* and /dev/dxg open handles (not GPU activity)")
	jsonOutput := flags.Bool("json", false, "output a JSON snapshot")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: portwho [--all] [--devices] [--json]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "portwho: unexpected positional arguments")
		return 2
	}
	r, err := collect(ports.Options{All: *all, Devices: *devices})
	if err != nil {
		fmt.Fprintln(stderr, "portwho:", err)
		return 1
	}
	if *jsonOutput {
		sink := &stickyWriter{out: out}
		e := json.NewEncoder(sink)
		e.SetIndent("", "  ")
		err = e.Encode(r)
	} else {
		fmt.Fprintln(stderr, "Scope:", safe(r.Scope))
		for _, w := range r.Warnings {
			fmt.Fprintln(stderr, "Warning:", safe(w))
		}
		err = render(out, r, *devices)
	}
	if err != nil {
		fmt.Fprintln(stderr, "portwho: output:", err)
		return 1
	}
	return 0
}

// Replace terminal controls and Unicode format characters (including bidi
// overrides) so process metadata cannot inject rows or conceal displayed text.
func safe(s string) string {
	if s == "" {
		return "?"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '\uFFFD'
		}
		return r
	}, s)
}

// Preserve the first error even when tabwriter performs intermediate flushes.
type stickyWriter struct {
	out io.Writer
	err error
}

func (w *stickyWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.out.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func render(out io.Writer, r ports.Result, devices bool) error {
	sink := &stickyWriter{out: out}
	w := tabwriter.NewWriter(sink, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROTO\tLOCAL\tREMOTE\tSTATE\tSOCKET_UID\tPID\tNAME\tEXECUTABLE\tPROC_UID\tUSER\tCONTAINER")
	for _, s := range r.Sockets {
		owners := s.Owners
		if len(owners) == 0 {
			owners = []ports.Process{{}}
		}
		for _, p := range owners {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", safe(s.Protocol), safe(s.Local), safe(s.Remote), safe(s.State), safe(s.UID), processColumns(p))
		}
	}
	if devices {
		fmt.Fprintln(w, "\nDEVICE\tPID\tNAME\tEXECUTABLE\tPROC_UID\tUSER\tCONTAINER")
		for _, d := range r.Devices {
			for _, p := range d.Owners {
				fmt.Fprintf(w, "%s\t%s\n", safe(d.Path), processColumns(p))
			}
		}
	}
	err := w.Flush()
	if sink.err != nil {
		return sink.err
	}
	return err
}

func processColumns(p ports.Process) string {
	pid := "?"
	if p.PID > 0 {
		pid = strconv.Itoa(p.PID)
	}
	return strings.Join([]string{pid, safe(p.Name), safe(p.Executable), safe(p.UID), safe(p.User), safe(p.Container)}, "\t")
}
