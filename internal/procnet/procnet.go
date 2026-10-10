// Package procnet reads listening TCP sockets from /proc/net/tcp{,6}.
package procnet

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type Listener struct {
	Port      uint64
	AllIfaces bool   // bound to 0.0.0.0 or ::
	Src       string // file it was read from
}

// Default are the standard Linux tables.
var Default = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// Listeners returns every socket in LISTEN state (0A) found in the given tables.
func Listeners(paths ...string) []Listener {
	var out []Listener
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 4 || fl[3] != "0A" {
				continue
			}
			i := strings.LastIndexByte(fl[1], ':')
			if i < 0 {
				continue
			}
			port, err := strconv.ParseUint(fl[1][i+1:], 16, 16)
			if err != nil {
				continue
			}
			out = append(out, Listener{port, strings.Trim(fl[1][:i], "0") == "", p})
		}
		f.Close()
	}
	return out
}

// Listening reports whether anything listens on port.
func Listening(paths []string, port uint64) bool {
	for _, l := range Listeners(paths...) {
		if l.Port == port {
			return true
		}
	}
	return false
}
