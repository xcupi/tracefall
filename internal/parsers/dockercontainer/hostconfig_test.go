package dockercontainer

import (
	"strings"
	"testing"
)

const privHost = `{"Binds":["/var/run/docker.sock:/var/run/docker.sock","/etc/app:/cfg:ro","/srv/data:/data","/:/host","/etcetera:/x","/var/lib/docker/volumes:/v"],"ContainerIDFile":"","NetworkMode":"host","PortBindings":{"80/tcp":[{"HostIp":"","HostPort":"8080"}],"443/tcp":[{"HostIp":"0.0.0.0","HostPort":"8443"}],"53/udp":[{"HostIp":"127.0.0.1","HostPort":"5353"}]},` +
	`"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":3},"CapAdd":["SYS_ADMIN","CAP_SYS_PTRACE","NET_BIND_SERVICE"],"CapDrop":["MKNOD"],"IpcMode":"host","PidMode":"host","Privileged":true,"PublishAllPorts":false,"ReadonlyRootfs":true,"SecurityOpt":["seccomp=unconfined","apparmor=unconfined"],"UsernsMode":"host","Devices":[{"PathOnHost":"/dev/fuse"},{"PathOnHost":"/dev/kvm"}],"Memory":536870912}`

func TestHostConfig_PrivilegedWithSocketMount(t *testing.T) {
	r := parse(t, writeIn(t, cid, "hostconfig.json", privHost))
	if len(r.Events) != 1 {
		t.Fatalf("events = %d", len(r.Events))
	}
	e := r.Events[0]
	if e.EventType != "container_host_config" || e.ArtifactType != "container_config" || !e.Timestamp.IsZero() {
		t.Errorf("event = %s %s %v", e.EventType, e.ArtifactType, e.Timestamp)
	}
	want := map[string]string{
		"container_id":       cid,
		"privileged":         "true",
		"network_mode":       "host",
		"pid_mode":           "host",
		"ipc_mode":           "host",
		"userns_mode":        "host",
		"cap_add":            "SYS_ADMIN,CAP_SYS_PTRACE,NET_BIND_SERVICE",
		"cap_drop":           "MKNOD",
		"security_opt":       "seccomp=unconfined,apparmor=unconfined",
		"binds":              "/:/host,/etc/app:/cfg:ro,/etcetera:/x,/srv/data:/data,/var/lib/docker/volumes:/v,/var/run/docker.sock:/var/run/docker.sock",
		"port_bindings":      "0.0.0.0:8443->443/tcp,127.0.0.1:5353->53/udp,:8080->80/tcp",
		"restart_policy":     "on-failure:3",
		"readonly_rootfs":    "true",
		"devices":            "2",
		"memory_limit_bytes": "536870912",
		"risky":              "cap_sys_admin,cap_sys_ptrace,docker_socket_mount,host_network,host_pid,host_root_mount,privileged,published_all_interfaces,sensitive_host_mount",
	}
	for k, v := range want {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	if !strings.Contains(e.Extra["records_outcome"], "does not show what ran inside the container") {
		t.Errorf("records_outcome = %q", e.Extra["records_outcome"])
	}
	if e.FilePath != cid+"/hostconfig.json" || e.Parser != "dockercontainer@1" || r.Raw[0].SourceReference != e.SourceReference {
		t.Errorf("provenance = %+v", e)
	}
}

func TestHostConfig_PlainContainerHasNoRiskTags(t *testing.T) {
	body := `{"Binds":null,"NetworkMode":"bridge","PortBindings":{"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"13000"}]},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"CapAdd":null,"CapDrop":null,"IpcMode":"private","PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UsernsMode":"","Devices":[],"Memory":0}`
	e := parse(t, writeIn(t, cid, "hostconfig.json", body)).Events[0]
	want := map[string]string{"privileged": "false", "risky": "", "port_bindings": "127.0.0.1:13000->3000/tcp", "restart_policy": "no", "devices": "0", "binds": "", "readonly_rootfs": "false", "network_mode": "bridge"}
	for k, v := range want {
		if got, ok := e.Extra[k]; !ok || got != v {
			t.Errorf("Extra[%s] = %q (present %v), want %q", k, got, ok, v)
		}
	}
}

func TestHostConfig_WindowsBindsAndNamedPipe(t *testing.T) {
	body := `{"Binds":["C:\\data:C:\\app","\\\\.\\pipe\\docker_engine:\\\\.\\pipe\\docker_engine","D:\\:C:\\d","C:\\Users:C:\\u"],"NetworkMode":"nat","PortBindings":{},"Privileged":false}`
	e := parse(t, writeIn(t, cid, "hostconfig.json", body)).Events[0]
	if e.Extra["risky"] != "docker_socket_mount,host_root_mount" {
		t.Errorf("risky = %q", e.Extra["risky"])
	}
	if !strings.Contains(e.Extra["binds"], `C:\data:C:\app`) {
		t.Errorf("binds = %q", e.Extra["binds"])
	}
}

func TestHostConfig_MountFlagBindsCountToo(t *testing.T) {
	body := `{"NetworkMode":"bridge","Privileged":false,"Mounts":[{"Type":"bind","Source":"/run/docker.sock","Target":"/s","ReadOnly":true},{"Type":"volume","Source":"dbvol","Target":"/db"},{"Type":"bind","Source":"/root","Target":"/r"}]}`
	e := parse(t, writeIn(t, cid, "hostconfig.json", body)).Events[0]
	if e.Extra["risky"] != "docker_socket_mount,sensitive_host_mount" {
		t.Errorf("risky = %q", e.Extra["risky"])
	}
	if e.Extra["host_mounts"] != "bind:/root->/r,bind:/run/docker.sock->/s:ro,volume:dbvol->/db" {
		t.Errorf("host_mounts = %q", e.Extra["host_mounts"])
	}
}

func TestHostConfig_RejectsWhatIsNotAHostConfig(t *testing.T) {
	for name, body := range map[string]string{
		"not json":           "{",
		"no NetworkMode":     `{"Privileged":false}`,
		"neither Ports/Priv": `{"NetworkMode":"bridge"}`,
		"array":              `[]`,
	} {
		if r, err := New().Parse(writeIn(t, cid, "hostconfig.json", body)); err == nil {
			t.Errorf("%s: want error, got %d events", name, len(r.Events))
		}
	}
	if _, err := New().Parse(writeIn(t, "plain", "hostconfig.json", privHost)); err == nil {
		t.Error("hostconfig.json outside an id directory must not be parsed")
	}
}

func TestHostConfig_DeterministicNoLeak(t *testing.T) {
	p := writeIn(t, cid, "hostconfig.json", privHost)
	a, b := parse(t, p), parse(t, p)
	if len(a.Events) != 1 || a.Events[0].Extra["risky"] != b.Events[0].Extra["risky"] || a.Raw[0] != b.Raw[0] {
		t.Error("two parses differ")
	}
}
