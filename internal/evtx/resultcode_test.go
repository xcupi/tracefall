package evtx

import "testing"

func TestExtractDataResultCodeLiteral(t *testing.T) {
	for _, value := range []string{"", "0", " 0x00000000 ", "\u00a0\u2003\t0\r\n\u202f", "\t\r\n", "-", "not-a-number", "00", "0xZZ", "0<&\"'"} {
		for _, section := range []string{"EventData", "UserData"} {
			for _, nested := range []bool{false, true} {
				for _, named := range []bool{false, true} {
					leaf := &node{name: "ResultCode", text: value}
					if named {
						leaf.name = "Data"
						leaf.attrs = map[string]string{"Name": "ResultCode"}
					}
					root := &node{name: section, children: []*node{leaf}}
					if nested {
						root.children = []*node{{name: "Payload", children: root.children}}
					}
					got := map[string]string{}
					extractData(root, got, 0)
					if actual, present := got["ResultCode"]; !present || actual != value {
						t.Errorf("%s nested=%t named=%t: ResultCode = %q (%t), want %q", section, nested, named, actual, present, value)
					}
				}
			}
		}
	}
	got := map[string]string{}
	extractData(&node{name: "EventData"}, got, 0)
	if _, present := got["ResultCode"]; present {
		t.Fatal("missing ResultCode fabricated")
	}
}

func TestExtractDataOtherFieldsKeepTrimContract(t *testing.T) {
	got := map[string]string{}
	extractData(&node{children: []*node{
		{name: "Data", attrs: map[string]string{"Name": "TaskName"}, text: " \ttask\r\n"},
		{name: "Data", text: " \tHostApplication=tool.exe\r\n "},
		{name: "Data", text: " \t\r\n "},
		{name: "Other", text: " \tvalue\r\n "},
		{name: "Data", attrs: map[string]string{"Name": "resultcode"}, text: " 0 "},
	}}, got, 0)
	if len(got) != 4 || got["TaskName"] != "task" || got["Data2"] != "HostApplication=tool.exe" || got["Other"] != "value" || got["resultcode"] != "0" {
		t.Fatalf("unrelated field contract changed: %#v", got)
	}
}
