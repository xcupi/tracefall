package cmdsem

import (
	"strings"
	"testing"
)

func has(sems []Semantic, cat, action string) (Semantic, bool) {
	for _, s := range sems {
		if s.Category == cat && s.Action == action {
			return s, true
		}
	}
	return Semantic{}, false
}

func TestAnalyze_Firewall(t *testing.T) {
	cases := []struct {
		cmd, cat, action, sev string
		detailHas             string
	}{
		{`netsh advfirewall firewall add rule name="Allow 4444" dir=in action=allow protocol=TCP localport=4444`, Firewall, "rule_added", Low, "localport=4444"},
		{`netsh advfirewall set allprofiles state off`, Firewall, "firewall_disabled", Medium, ""},
		{`netsh firewall set opmode disable`, Firewall, "firewall_disabled", Medium, ""},
		{`netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.0.0.5 connectport=80`, Firewall, "port_forward", Medium, ""},
		{`/sbin/iptables -A INPUT -p tcp --dport 22 -s 203.0.113.9 -j DROP`, Firewall, "rule_added", Low, "port 22 from 203.0.113.9"},
		{`iptables -F`, Firewall, "rules_flushed", Medium, ""},
		{`iptables -P INPUT ACCEPT`, Firewall, "policy_accept_all", Medium, "INPUT"},
		{`iptables -P FORWARD DROP`, Firewall, "policy_set", Low, "FORWARD"},
		{`iptables -D INPUT 3`, Firewall, "rule_deleted", Low, ""},
		{`ufw disable`, Firewall, "firewall_disabled", Medium, ""},
		{`systemctl stop firewalld`, Firewall, "firewall_disabled", Medium, ""},
		{`Set-NetFirewallProfile -Profile Domain,Public -Enabled False`, Firewall, "firewall_disabled", Medium, ""},
	}
	for _, c := range cases {
		s, ok := has(Analyze(c.cmd), c.cat, c.action)
		if !ok {
			t.Errorf("%q: no %s/%s in %+v", c.cmd, c.cat, c.action, Analyze(c.cmd))
			continue
		}
		if s.Severity != c.sev {
			t.Errorf("%q: severity %s, want %s", c.cmd, s.Severity, c.sev)
		}
		if !strings.Contains(s.Detail, c.detailHas) {
			t.Errorf("%q: detail %q lacks %q", c.cmd, s.Detail, c.detailHas)
		}
		if s.Technique == "" {
			t.Errorf("%q: no technique", c.cmd)
		}
	}
}

func TestAnalyze_Persistence(t *testing.T) {
	cases := []struct{ cmd, action, sev string }{
		{`schtasks /create /tn Updater /tr C:\Users\Public\u.exe /sc minute /mo 5`, "scheduled_task_created", Medium},
		{`sc create svc01 binpath= C:\Windows\Temp\s.exe start= auto`, "service_created", Medium},
		{`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d C:\t\x.exe`, "run_key_set", Medium},
		{`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /d cmd.exe`, "ifeo_set", High},
		{`crontab -e`, "cron_installed", Medium},
		{`crontab /tmp/jobs`, "cron_installed", Medium},
		{`echo "* * * * * /tmp/x" >> /etc/crontab`, "cron_installed", Medium},
		{`systemctl enable backdoor.service`, "service_enabled", Low},
		{`echo 'ssh-rsa AAAA' >> /home/alice/.ssh/authorized_keys`, "ssh_key_added", High},
		{`echo /tmp/x >> ~/.bashrc`, "shell_profile_edit", Medium},
	}
	for _, c := range cases {
		s, ok := has(Analyze(c.cmd), Persistence, c.action)
		if !ok {
			t.Errorf("%q: no %s in %+v", c.cmd, c.action, Analyze(c.cmd))
			continue
		}
		if s.Severity != c.sev {
			t.Errorf("%q: severity %s want %s", c.cmd, s.Severity, c.sev)
		}
	}
	if s, _ := has(Analyze(`schtasks /create /tn Updater /tr C:\u.exe /sc daily`), Persistence, "scheduled_task_created"); !strings.Contains(s.Detail, "/tn Updater") || !strings.Contains(s.Detail, `/tr C:\u.exe`) {
		t.Errorf("task detail: %q", s.Detail)
	}
}

func TestAnalyze_Accounts(t *testing.T) {
	s, ok := has(Analyze(`net user carol Sup3rS3cret! /add`), Account, "user_added")
	if !ok || s.Detail != "Local account added: carol" {
		t.Fatalf("net user add: %+v", s)
	}
	for _, c := range Analyze(`net user carol Sup3rS3cret! /add`) {
		if strings.Contains(c.Detail, "Sup3rS3cret") {
			t.Fatalf("a password must never reach a Semantic: %q", c.Detail)
		}
	}
	if _, ok := has(Analyze(`net user carol /add`), Account, "user_added"); !ok {
		t.Error("net user without a password")
	}
	g, ok := has(Analyze(`net localgroup administrators carol /add`), Account, "group_member_added")
	if !ok || g.Severity != High || !strings.Contains(g.Detail, "privileged group") {
		t.Errorf("admin group add: %+v", g)
	}
	g2, ok := has(Analyze(`net localgroup "Print Operators" carol /add`), Account, "group_member_added")
	if !ok || g2.Severity != Medium {
		t.Errorf("non-privileged group: %+v", g2)
	}
	if p, ok := has(Analyze(`net user carol NewPass1`), Account, "password_set"); !ok || strings.Contains(p.Detail, "NewPass1") {
		t.Errorf("password set must name the account only: %+v", p)
	}
	if u, ok := has(Analyze(`useradd -m -s /bin/bash -u 0 -o toor`), Account, "user_added"); !ok || u.Severity != High {
		t.Errorf("UID 0 account: %+v", u)
	}
	if u, ok := has(Analyze(`useradd -m dave`), Account, "user_added"); !ok || u.Detail != "Local account added: dave" || u.Severity != Medium {
		t.Errorf("plain useradd: %+v", u)
	}
	if m, ok := has(Analyze(`usermod -aG sudo dave`), Account, "group_member_added"); !ok || m.Severity != High {
		t.Errorf("usermod -aG sudo: %+v", m)
	}
}

func TestAnalyze_ListingAndNoiseHaveNoSemantic(t *testing.T) {
	for _, cmd := range []string{
		"", "   ", "iptables -L -n", "iptables -S", "crontab -l", "crontab -r", "net user", "net user carol",
		"net localgroup administrators", "systemctl status firewalld", "systemctl enable", "ls -l /etc/cron.d",
		"cat /etc/crontab", "sc query mpssvc", "netsh advfirewall show allprofiles", "ufw status",
	} {
		if got := Analyze(cmd); len(got) != 0 {
			t.Errorf("%q must carry no semantic, got %+v", cmd, got)
		}
	}
}

func TestAnalyze_IsDeterministic(t *testing.T) {
	cmd := `iptables -F && iptables -P INPUT ACCEPT && iptables -A INPUT -j ACCEPT; ufw disable`
	a, b := Analyze(cmd), Analyze(cmd)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("%d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("order differs at %d", i)
		}
	}
}

func TestRedact_MasksKnownSecretShapes(t *testing.T) {
	cases := []struct{ in, secret string }{
		{`net user carol Sup3rS3cret! /add`, "Sup3rS3cret"},
		{`net1 user carol NewPass1`, "NewPass1"},
		{`echo "carol:Hunter2x" | chpasswd`, "Hunter2x"},
		{`useradd -m -p 5up3rhash carol`, "5up3rhash"},
		{`sshpass -p Tr0ub4dor ssh carol@203.0.113.5`, "Tr0ub4dor"},
		{`mysql -u root -pRootPw1 -e "select 1"`, "RootPw1"},
		{`schtasks /create /tn t /tr x.exe /sc daily /ru carol /rp Passw0rd!`, "Passw0rd"},
		{`New-LocalUser carol -Password (ConvertTo-SecureString "Pl41ntext" -AsPlainText -Force)`, "Pl41ntext"},
	}
	for _, c := range cases {
		got := Redact(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("%q still contains %q: %q", c.in, c.secret, got)
		}
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("%q: nothing was masked: %q", c.in, got)
		}
	}
}

func TestRedact_LeavesOrdinaryCommandsAlone(t *testing.T) {
	for _, cmd := range []string{
		"iptables -A INPUT -p tcp --dport 22 -j DROP", "net user carol /add", "net localgroup administrators carol /add",
		"crontab -e", "ls -l /etc", "schtasks /create /tn t /tr x.exe /sc daily", "useradd -m carol",
	} {
		if got := Redact(cmd); got != cmd {
			t.Errorf("%q changed to %q", cmd, got)
		}
	}
}
