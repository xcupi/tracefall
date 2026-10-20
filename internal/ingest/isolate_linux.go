//go:build linux

package ingest

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func workerEnv(memMB int, sandboxed bool) []string {
	tmp := os.TempDir()
	if sandboxed {
		tmp = "/tmp" // a private tmpfs inside the sandbox
	}
	return []string{
		"TRACEFALL_PARSER_MEM_MB=" + strconv.Itoa(memMB),
		"TMPDIR=" + tmp,
		"PATH=/usr/bin:/bin",
	}
}

// sandboxArgs is the bubblewrap command line for one worker: new user, pid,
// ipc, uts, cgroup and network namespaces (so no interfaces but a down
// loopback), no capabilities, and a file system that holds only what the
// worker needs. Everything is read-only except a private /tmp.
func sandboxArgs(exe, root string) []string {
	args := []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
	}
	for _, d := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		args = append(args, "--ro-bind-try", d, d)
	}
	args = append(args, "--ro-bind", exe, exe, "--ro-bind", root, root, exe, "parse-worker")
	return args
}

// FindSandbox returns the path of bubblewrap when it can start an unprivileged
// sandbox with no network on this system, else "".
func FindSandbox() string {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return ""
	}
	probe := exec.Command(path, "--unshare-all", "--ro-bind-try", "/usr", "/usr", "--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64", "/bin/true")
	if probe.Run() != nil {
		return ""
	}
	return path
}

// configureChild makes the worker die with the server, and, when asked, puts
// it in a user and network namespace with no interfaces, so a parser cannot
// open a connection. Both namespaces are created unprivileged.
func configureChild(cmd *exec.Cmd, noNetwork bool) {
	// Its own process group, so a stop reaches everything it started, not just
	// the first process.
	attr := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if noNetwork {
		attr.Cloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}
		attr.GidMappingsEnableSetgroups = false
	}
	cmd.SysProcAttr = attr
}

// NetworkIsolationAvailable reports whether this kernel lets an unprivileged
// process start a child in its own empty network namespace.
func NetworkIsolationAvailable() bool {
	cmd := exec.Command("/bin/true")
	configureChild(cmd, true)
	return cmd.Run() == nil
}

// ApplyWorkerLimits restricts the worker process itself: address space, core
// dumps, open files, and no gaining of privileges. It returns what it applied.
func ApplyWorkerLimits() (applied []string, err error) {
	mem := 4096
	if v, e := strconv.Atoi(os.Getenv("TRACEFALL_PARSER_MEM_MB")); e == nil && v > 0 {
		mem = v
	}
	set := func(res int, n uint64, name string) error {
		if err := syscall.Setrlimit(res, &syscall.Rlimit{Cur: n, Max: n}); err != nil {
			return err
		}
		applied = append(applied, name)
		return nil
	}
	if err := set(syscall.RLIMIT_AS, uint64(mem)<<20, "address-space"); err != nil {
		return applied, err
	}
	if err := set(syscall.RLIMIT_CORE, 0, "no-core-dump"); err != nil {
		return applied, err
	}
	if err := set(syscall.RLIMIT_NOFILE, 256, "open-files"); err != nil {
		return applied, err
	}
	// PR_SET_NO_NEW_PRIVS
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 38, 1, 0); e != 0 {
		return applied, e
	}
	applied = append(applied, "no-new-privileges")
	return applied, nil
}
