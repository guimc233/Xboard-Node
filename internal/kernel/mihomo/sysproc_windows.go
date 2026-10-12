//go:build windows

package mihomo

import "syscall"

// newSysProcAttr returns nil on Windows: there is no process-group equivalent
// that the agent needs here.
func newSysProcAttr() *syscall.SysProcAttr {
	return nil
}
