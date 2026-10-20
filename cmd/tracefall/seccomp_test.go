package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"tracefall/internal/ingest"
)

// probeCall is one system call the worker's filter is meant to refuse. The
// arguments are chosen so that, without the filter, the kernel answers with an
// error other than EPERM (EBADF, ENOENT, EFAULT ...). That makes the probe
// meaningful: the same call in a process without the filter must NOT return
// EPERM, and in a process with it must.
type probeCall struct {
	name string
	nr   uintptr
	args [6]uintptr
}

// The numbers are written out here on purpose, independently of the table in
// the code under test, and checked against the kernel headers for both
// architectures.
func probeCalls() []probeCall {
	bad := uintptr(^uintptr(0)) // -1: an invalid descriptor
	empty, _ := syscall.BytePtrFromString("")
	missing, _ := syscall.BytePtrFromString("/nonexistent/program")
	var c []probeCall
	add := func(name string, nr uintptr, a ...uintptr) {
		p := probeCall{name: name, nr: nr}
		copy(p.args[:], a)
		c = append(c, p)
	}
	add("execve", syscall.SYS_EXECVE, uintptr(unsafe.Pointer(missing)), 0, 0)
	add("socket", syscall.SYS_SOCKET, syscall.AF_INET, syscall.SOCK_STREAM, 0)
	add("connect", syscall.SYS_CONNECT, bad, 0, 0)
	add("bind", syscall.SYS_BIND, bad, 0, 0)
	add("listen", syscall.SYS_LISTEN, bad, 1)
	add("chroot", syscall.SYS_CHROOT, uintptr(unsafe.Pointer(missing)))
	add("io_uring_setup", 425, 0, 0)
	add("open_tree", 428, bad, uintptr(unsafe.Pointer(empty)), 0)
	switch runtime.GOARCH {
	case "amd64":
		add("execveat", 322, bad, uintptr(unsafe.Pointer(empty)), 0, 0, 0)
		add("setns", 308, bad, 0)
		add("process_vm_readv", 310, 0, 0, 0, 0, 0, 0)
		add("bpf", 321, 0x7fff, 0, 0)
		add("finit_module", 313, bad, uintptr(unsafe.Pointer(empty)), 0)
	case "arm64":
		add("execveat", 281, bad, uintptr(unsafe.Pointer(empty)), 0, 0, 0)
		add("setns", 268, bad, 0)
		add("process_vm_readv", 270, 0, 0, 0, 0, 0, 0)
		add("bpf", 280, 0x7fff, 0, 0)
		add("finit_module", 273, bad, uintptr(unsafe.Pointer(empty)), 0)
	}
	return c
}

// runProbe performs every call from several threads and prints, per call, the
// errno it got (0 means the call succeeded).
func runProbe(applyLimits bool) {
	var applied []string
	var lerr string
	if applyLimits {
		var err error
		applied, err = ingest.ApplyWorkerLimits()
		if err != nil {
			lerr = err.Error()
		}
	}
	// Threads that exist before and after the filter: all must be covered.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { runtime.LockOSThread(); wg.Done(); select {} }()
	}
	wg.Wait()

	res := map[string]any{"applied": applied, "limits_error": lerr}
	errnos := map[string]int{}
	for _, p := range probeCalls() {
		// from a thread of its own, not the one that installed the filter
		done := make(chan int)
		go func() {
			runtime.LockOSThread()
			r, _, e := syscall.RawSyscall6(p.nr, p.args[0], p.args[1], p.args[2], p.args[3], p.args[4], p.args[5])
			if e == 0 && p.name == "socket" {
				syscall.Close(int(r))
			}
			done <- int(e)
		}()
		errnos[p.name] = <-done
	}
	res["errnos"] = errnos

	// What a parser does must keep working under the filter.
	ok := map[string]bool{}
	_, err := os.ReadFile("/proc/self/status")
	ok["read a file"] = err == nil
	_, err = os.Stat(os.Args[0])
	ok["stat"] = err == nil
	buf := make([]byte, 64<<20)
	buf[len(buf)-1] = 1
	ok["allocate 64 MiB"] = buf[len(buf)-1] == 1
	var m sync.Mutex
	n := 0
	var w sync.WaitGroup
	for i := 0; i < 16; i++ {
		w.Add(1)
		go func() { defer w.Done(); m.Lock(); n++; m.Unlock() }()
	}
	w.Wait()
	ok["goroutines"] = n == 16
	tmp, err := os.CreateTemp("", "probe")
	if err == nil {
		_, err = tmp.WriteString("x")
		tmp.Close()
		os.Remove(tmp.Name())
	}
	ok["write a temp file"] = err == nil
	res["works"] = ok
	_ = json.NewEncoder(os.Stdout).Encode(res)
}

type probeResult struct {
	Applied     []string        `json:"applied"`
	LimitsError string          `json:"limits_error"`
	Errnos      map[string]int  `json:"errnos"`
	Works       map[string]bool `json:"works"`
}

func runSelf(t *testing.T, mode string) probeResult {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(exe, mode).Output()
	if err != nil {
		t.Fatalf("%s: %v", mode, err)
	}
	var r probeResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("%s: unreadable output %q", mode, out)
	}
	return r
}

func TestSeccomp_RefusesWhatNoParserNeedsAndKeepsParsingWorking(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("the filter is built for linux on amd64 and arm64")
	}
	control := runSelf(t, "seccompcontrol")
	filtered := runSelf(t, "seccompprobe")

	if filtered.LimitsError != "" {
		t.Skipf("this kernel did not accept the filter: %s", filtered.LimitsError)
	}
	hasSeccomp := false
	for _, a := range filtered.Applied {
		hasSeccomp = hasSeccomp || a == "seccomp"
	}
	if !hasSeccomp {
		t.Fatalf("seccomp is missing from what the worker reports as applied: %v", filtered.Applied)
	}

	eperm := int(syscall.EPERM)
	distinguishable := 0
	for _, p := range probeCalls() {
		c, f := control.Errnos[p.name], filtered.Errnos[p.name]
		if c == eperm {
			t.Logf("%-18s cannot be told apart here (the unfiltered call is already EPERM)", p.name)
			continue
		}
		distinguishable++
		if f != eperm {
			t.Errorf("%-18s unfiltered errno=%d, filtered errno=%d: want EPERM", p.name, c, f)
		}
	}
	if distinguishable < 8 {
		t.Fatalf("only %d calls could be checked; the probe is too weak", distinguishable)
	}
	t.Logf("%d refused system calls verified against an unfiltered control", distinguishable)

	for what, ok := range filtered.Works {
		if !ok {
			t.Errorf("under the filter this stopped working: %s", what)
		}
	}
	if len(filtered.Works) < 5 {
		t.Errorf("only %d ordinary operations were exercised", len(filtered.Works))
	}
}

// A process that starts a program is the typical post-exploitation step.
func TestSeccomp_ACompromisedWorkerCannotStartAProgram(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip()
	}
	exe, _ := os.Executable()
	out, err := exec.Command(exe, "seccompspawn").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if string(out) != "blocked\n" {
		t.Fatalf("got %q, want the spawn to be blocked", out)
	}
}

func spawnProbe() {
	if _, err := ingest.ApplyWorkerLimits(); err != nil {
		os.Stdout.WriteString("no filter: " + err.Error() + "\n")
		return
	}
	err := exec.Command("/bin/true").Run()
	if err == nil {
		os.Stdout.WriteString("STARTED\n")
		return
	}
	os.Stdout.WriteString("blocked\n")
}
