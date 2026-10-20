//go:build linux && (amd64 || arm64)

package ingest

import (
	"fmt"
	"syscall"
	"unsafe"
)

// A parser reads one file and returns events. It has no reason to start a
// program, open a socket, trace another process, load a module, change mounts
// or namespaces, or use the kernel facilities that are common routes out of a
// compromised process. The worker installs a seccomp filter that refuses those
// system calls, so a parser bug that gives an attacker code execution still
// finds them closed.
//
// This is a deny list, not an allow list. An allow list is the stronger form
// but has to name every system call the Go runtime and every parser might use,
// on every kernel and architecture; a missing one kills the worker in
// production. The deny list is chosen so that the calls it refuses are ones no
// parser path uses, which the tests exercise.

// Not in the syscall package for these architectures, but the same number on
// both (the unified system call table).
const (
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427
	sysOpenTree        = 428
	sysMoveMount       = 429
	sysFsopen          = 430
	sysFsconfig        = 431
	sysFsmount         = 432
	sysFspick          = 433
	sysMountSetattr    = 442
)

// deniedSyscalls are refused with EPERM.
var deniedSyscalls = map[string]uintptr{
	// start another program
	"execve":   syscall.SYS_EXECVE,
	"execveat": sysExecveat,
	// network
	"socket":  syscall.SYS_SOCKET,
	"connect": syscall.SYS_CONNECT,
	"bind":    syscall.SYS_BIND,
	"listen":  syscall.SYS_LISTEN,
	// look into or control other processes
	"ptrace":            syscall.SYS_PTRACE,
	"process_vm_readv":  sysProcessVMReadv,
	"process_vm_writev": sysProcessVMWritev,
	// the kernel
	"kexec_load":      syscall.SYS_KEXEC_LOAD,
	"init_module":     syscall.SYS_INIT_MODULE,
	"finit_module":    sysFinitModule,
	"delete_module":   syscall.SYS_DELETE_MODULE,
	"bpf":             sysBpf,
	"perf_event_open": syscall.SYS_PERF_EVENT_OPEN,
	"userfaultfd":     sysUserfaultfd,
	"reboot":          syscall.SYS_REBOOT,
	// file system and namespace changes
	"mount":         syscall.SYS_MOUNT,
	"umount2":       syscall.SYS_UMOUNT2,
	"pivot_root":    syscall.SYS_PIVOT_ROOT,
	"chroot":        syscall.SYS_CHROOT,
	"unshare":       syscall.SYS_UNSHARE,
	"setns":         sysSetns,
	"open_tree":     sysOpenTree,
	"move_mount":    sysMoveMount,
	"fsopen":        sysFsopen,
	"fsconfig":      sysFsconfig,
	"fsmount":       sysFsmount,
	"fspick":        sysFspick,
	"mount_setattr": sysMountSetattr,
	// credentials stores
	"keyctl":      syscall.SYS_KEYCTL,
	"add_key":     syscall.SYS_ADD_KEY,
	"request_key": syscall.SYS_REQUEST_KEY,
	// a second, unfiltered path to the file system and network
	"io_uring_setup":    sysIoUringSetup,
	"io_uring_enter":    sysIoUringEnter,
	"io_uring_register": sysIoUringRegister,
}

const (
	bpfLdWAbs   = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJmpJeqK  = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJmpJgeK  = 0x35 // BPF_JMP | BPF_JGE | BPF_K
	bpfRetK     = 0x06 // BPF_RET | BPF_K
	seccompData = 0    // offset of nr in struct seccomp_data
	archOffset  = 4    // offset of arch

	retAllow       = 0x7fff0000
	retKillProcess = 0x80000000
	retErrnoPerm   = 0x00050000 | uint32(syscall.EPERM)

	seccompSetModeFilter = 1
	filterFlagTSYNC      = 1
	prSetSeccomp         = 22
	seccompModeFilter    = 2
)

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *sockFilter
}

// buildSeccompProgram assembles the filter:
//
//	wrong architecture            -> kill (a 32-bit or x32 entry could skip the list)
//	a listed system call          -> EPERM
//	anything else                 -> allow
func buildSeccompProgram() []sockFilter {
	var p []sockFilter
	ld := func(off uint32) { p = append(p, sockFilter{Code: bpfLdWAbs, K: off}) }

	ld(archOffset)
	p = append(p,
		sockFilter{Code: bpfJmpJeqK, Jt: 1, Jf: 0, K: auditArch},
		sockFilter{Code: bpfRetK, K: retKillProcess},
	)
	ld(seccompData)
	if x32Mask != 0 {
		// x86-64 has a second numbering (x32) reached by setting a high bit.
		p = append(p,
			sockFilter{Code: bpfJmpJgeK, Jt: 0, Jf: 1, K: x32Mask},
			sockFilter{Code: bpfRetK, K: retKillProcess},
		)
	}
	nrs := sortedDenied()
	for i, nr := range nrs {
		// jump to the EPERM return at the end when equal
		toDeny := uint8(len(nrs) - i - 1 + 1) // skip remaining compares and the allow
		p = append(p, sockFilter{Code: bpfJmpJeqK, Jt: toDeny, Jf: 0, K: uint32(nr)})
	}
	p = append(p,
		sockFilter{Code: bpfRetK, K: retAllow},
		sockFilter{Code: bpfRetK, K: retErrnoPerm},
	)
	return p
}

func sortedDenied() []uintptr {
	seen := map[uintptr]bool{}
	var out []uintptr
	for _, nr := range deniedSyscalls {
		if !seen[nr] {
			seen[nr] = true
			out = append(out, nr)
		}
	}
	// stable order for reproducible programs
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// installSeccomp loads the filter on every thread of the process (TSYNC). It
// needs no-new-privileges to be set first.
func installSeccomp() error {
	prog := buildSeccompProgram()
	fprog := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, e := syscall.Syscall(sysSeccomp, seccompSetModeFilter, filterFlagTSYNC, uintptr(unsafe.Pointer(&fprog)))
	if e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	return nil
}

// DeniedSyscallNames lists what the filter refuses, for documentation and tests.
func DeniedSyscallNames() []string {
	var out []string
	for n := range deniedSyscalls {
		out = append(out, n)
	}
	return out
}
