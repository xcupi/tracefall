//go:build linux && amd64

package ingest

const (
	auditArch          = 0xC000003E
	x32Mask            = 0x40000000
	sysSeccomp         = 317
	sysExecveat        = 322
	sysSetns           = 308
	sysProcessVMReadv  = 310
	sysProcessVMWritev = 311
	sysFinitModule     = 313
	sysBpf             = 321
	sysUserfaultfd     = 323
)
