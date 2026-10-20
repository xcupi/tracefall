//go:build linux && arm64

package ingest

const (
	auditArch          = 0xC00000B7
	x32Mask            = 0
	sysSeccomp         = 277
	sysExecveat        = 281
	sysSetns           = 268
	sysProcessVMReadv  = 270
	sysProcessVMWritev = 271
	sysFinitModule     = 273
	sysBpf             = 280
	sysUserfaultfd     = 282
)
