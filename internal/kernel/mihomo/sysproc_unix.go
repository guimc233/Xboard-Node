//go:build !windows

package mihomo

import "syscall"

// newSysProcAttr isolates the child in its own process group on Unix so a
// signal aimed at the agent does not reach every node at once.
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
