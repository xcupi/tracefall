package store_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

func TestReviewBatchesRestartInterruptsWithoutResend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateCase(model.Case{ID: "case01", Name: "synthetic", Status: "created"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveBatchRun("case01", "run01", "running", map[string]any{"id": "run01", "state": "running"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveBatchPacket("case01", "run01", 0, "sending", map[string]any{"seq": 0, "state": "sending", "payload": map[string]any{"system": "exact system", "user": "exact user", "sha256": "synthetic digest"}, "attempted_at": "recorded"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, state, err := s.BatchRun("case01", "run01")
	if err != nil {
		t.Fatal(err)
	}
	if state != "interrupted" {
		t.Fatalf("restart lost uncertain delivery: got %q", state)
	}
	rows, err := s.BatchPackets("case01", "run01", -1, 8)
	if err != nil {
		t.Fatal(err)
	}
	var packet map[string]any
	json.Unmarshal(rows[0], &packet)
	if packet["state"] != "interrupted" || packet["payload"].(map[string]any)["user"] != "exact user" {
		t.Fatalf("interrupted packet not preserved: %v", packet)
	}
	ok, err := s.UpdateBatchPacket("case01", "run01", 0, "interrupted", "succeeded", map[string]any{})
	if err != nil || ok {
		t.Fatalf("stale worker revived interrupted run: %v %v", ok, err)
	}
	_, err = s.FreezeReviewSnapshot(context.Background(), "case01", "snapshot01")
	if err != nil {
		t.Fatal(err)
	}
}
