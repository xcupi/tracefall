package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

const iisHeader = "#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n#Date: 2026-01-05 00:00:03\r\n" +
	"#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes time-taken\r\n"

func TestDiscover_IISSiteLogsAreReadAndOtherW3CFoldersAreNot(t *testing.T) {
	root := t.TempDir()
	put := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	row := "2026-01-05 13:04:05 W3SVC1 WEB01 192.0.2.10 GET /a - 80 - 203.0.113.9 - - 200 0 0 1 1\r\n"
	put("inetpub/logs/LogFiles/W3SVC1/u_ex260105.log", iisHeader+row)
	put("inetpub/logs/LogFiles/FTPSVC2/u_ex260105.log", "#Software: Microsoft Internet Information Services 10.0\r\n#Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status\r\n2026-01-05 13:04:05 203.0.113.9 bob 192.0.2.10 21 USER bob 331\r\n")
	put("Windows/System32/LogFiles/HTTPERR/httperr1.log", "#Software: Microsoft HTTP API 2.0\r\n#Fields: date time c-ip c-port s-ip s-port cs-version cs-method cs-uri sc-status s-siteid s-reason s-queuename\r\n2026-01-05 13:04:05 203.0.113.9 1 192.0.2.10 80 HTTP/1.1 GET /x 400 - BadRequest -\r\n")
	files, err := Discover(root, Registry())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]DiscoveredFile{}
	for _, f := range files {
		by[filepath.ToSlash(f.Path)] = f
	}
	iis := by["inetpub/logs/LogFiles/W3SVC1/u_ex260105.log"]
	if !iis.Supported || iis.Parser != "iislog@1" || iis.ArtifactType != model.ArtifactIISLog {
		t.Errorf("IIS site log: %+v", iis)
	}
	if f := by["inetpub/logs/LogFiles/FTPSVC2/u_ex260105.log"]; f.Parser == "iislog@1" {
		t.Errorf("an FTP site log was read as a web log: %+v", f)
	}
	if f := by["Windows/System32/LogFiles/HTTPERR/httperr1.log"]; f.Parser == "iislog@1" {
		t.Errorf("an HTTP.sys error log was read as a web log: %+v", f)
	}
}
