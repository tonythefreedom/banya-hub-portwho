// Package ports discovers socket owners without executing external commands.
package ports

// Options controls the snapshot. By default only listening TCP and all UDP
// sockets are included. Device handles are an independent, optional inventory.
type Options struct {
	All     bool
	Devices bool
}

// Process is a best-effort owner description. Empty fields mean unknown.
// UID is the process real UID on Linux, or token user SID on Windows, not the
// socket UID. Container is a heuristic,
// never evidence that an unmarked process runs on the host.
type Process struct {
	PID        int    `json:"pid"`
	Name       string `json:"name,omitempty"`
	Executable string `json:"executable,omitempty"`
	UID        string `json:"uid,omitempty"`
	User       string `json:"user,omitempty"`
	Container  string `json:"container,omitempty"`
}

type Socket struct {
	Protocol string    `json:"protocol"`
	Local    string    `json:"local"`
	Remote   string    `json:"remote"`
	State    string    `json:"state"`
	UID      string    `json:"socket_uid,omitempty"`
	Inode    uint64    `json:"inode,omitempty"`
	Owners   []Process `json:"owners"`
}

type Device struct {
	Path   string    `json:"path"`
	Owners []Process `json:"owners"`
}

type Result struct {
	Sockets  []Socket `json:"sockets"`
	Devices  []Device `json:"devices"`
	Warnings []string `json:"warnings"`
	Scope    string   `json:"scope"`
}
