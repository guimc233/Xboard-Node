package buildinfo

import (
	"crypto/rand"
	"fmt"
)

// Overridden through -ldflags in release builds.
var (
	Version = "dev"
	Commit  = "unknown"
)

var Capabilities = []string{
	"report-v2",
	"source-isolated-devices",
	"normalized-outbounds-v2",
	"route-profiles-v1",
}

// InstanceID identifies this process boot. It is intentionally not persisted:
// a reconnect from a newer process must not share snapshot ownership with the
// process it replaced.
var InstanceID = newUUID()

func newUUID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("boot-%d", value)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
