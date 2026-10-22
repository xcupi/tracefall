package registry_test

import (
	"testing"
	"tracefall/internal/regf/regfgen"
)

func TestMSSQLUnknownAttributionRemainsUnknown(t *testing.T) {
	names := regfgen.NewKey("Instance Names", regfgen.NewKey("SQL").WithValues(regfgen.StringValue("ONE", "MSSQL16.LAB"), regfgen.StringValue("TWO", "MSSQL16.LAB")))
	inst := regfgen.NewKey("MSSQL16.LAB", regfgen.NewKey("Setup").WithValues(regfgen.StringValue("Version", "16.0")))
	root := regfgen.NewKey("SOFTWARE", regfgen.NewKey("Microsoft", regfgen.NewKey("Microsoft SQL Server", names, inst)))
	events := parseHive(t, writeHive(t, "SOFTWARE", regfgen.Build(`\??\C:\Windows\System32\config\SOFTWARE`, root)))
	found := false
	for _, e := range events {
		if e.Extra["registry_value_name"] == "Version" {
			found = true
			if e.Extra["instance"] != "" {
				t.Fatal("ambiguous mapping guessed", e)
			}
		}
	}
	if !found {
		t.Fatal("configuration lost")
	}
}

func TestMSSQLSharedSetupIsNotAnInstance(t *testing.T) {
	shared := regfgen.NewKey("160", regfgen.NewKey("Setup").WithValues(regfgen.StringValue("Version", "16.0")))
	root := regfgen.NewKey("SOFTWARE", regfgen.NewKey("Microsoft", regfgen.NewKey("Microsoft SQL Server", shared)))
	events := parseHive(t, writeHive(t, "SOFTWARE", regfgen.Build(`\??\C:\Windows\System32\config\SOFTWARE`, root)))
	for _, e := range events {
		if e.EventType == "sql_instance_configuration" {
			t.Fatal("shared component claimed as SQL instance", e)
		}
	}
}

func TestMSSQLRecordedConfiguration(t *testing.T) {
	names := regfgen.NewKey("Instance Names", regfgen.NewKey("SQL").WithValues(regfgen.StringValue("LAB", "MSSQL16.LAB")))
	setup := regfgen.NewKey("Setup").WithValues(regfgen.StringValue("SQLPath", `C:\Program Files\Microsoft SQL Server\MSSQL16.LAB\MSSQL`))
	params := regfgen.NewKey("Parameters").WithValues(regfgen.StringValue("SQLArg1", `-eC:\SQL\Log\ERRORLOG`))
	inst := regfgen.NewKey("MSSQL16.LAB", setup, regfgen.NewKey("MSSQLServer", params))
	root := regfgen.NewKey("SOFTWARE", regfgen.NewKey("Microsoft", regfgen.NewKey("Microsoft SQL Server", names, inst)))
	events := parseHive(t, writeHive(t, "SOFTWARE", regfgen.Build(`\??\C:\Windows\System32\config\SOFTWARE`, root)))
	count := 0
	for _, e := range events {
		if e.EventType != "sql_instance_configuration" {
			continue
		}
		count++
		if e.Extra["instance"] != "LAB" || e.Extra["instance_id"] != "MSSQL16.LAB" || e.Extra["records_execution"] != "false" || !e.Timestamp.IsZero() {
			t.Fatal(e)
		}
		if e.Extra["registry_value_data"] == "" || e.SourceReference == "" {
			t.Fatal(e)
		}
	}
	if count != 3 {
		t.Fatalf("SQL configuration records=%d want 3", count)
	}
}
