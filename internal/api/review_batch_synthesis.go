package api

import (
	"encoding/json"
	"sort"

	"tracefall/internal/model"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

func (s *Service) prepareBatchSynthesis(p ReviewBatchPlan, packets []ReviewBatchPacket) (ReviewBatchPacket, *narrative.ReviewPrepared, int, error) {
	in := narrative.ReviewInput{CaseID: p.CaseID, Names: p.Snapshot.Names}
	var commentary []narrative.Sentence
	var origins []int
	refs := map[narrative.Cite]bool{}
	for _, packet := range packets {
		if packet.Kind == "synthesis" || packet.State != "succeeded" {
			continue
		}
		commentary = append(commentary, packet.Sentences...)
		for range packet.Sentences {
			origins = append(origins, packet.Seq)
		}
		for _, sentence := range packet.Sentences {
			for _, c := range sentence.Cites {
				refs[c] = true
			}
		}
	}
	ids := make([]narrative.Cite, 0, len(refs))
	for c := range refs {
		ids = append(ids, c)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Kind != ids[j].Kind {
			return ids[i].Kind < ids[j].Kind
		}
		return ids[i].ID < ids[j].ID
	})
	eventSet := map[string]bool{}
	addEvent := func(id string) error {
		if eventSet[id] || len(in.Events) >= narrative.ReviewMaxEvents {
			return nil
		}
		e, ok, err := s.store.BatchEvent(p.CaseID, p.ID, id)
		if err != nil {
			return err
		}
		if ok {
			in.Events = append(in.Events, e)
			eventSet[id] = true
		}
		return nil
	}
	// First preserve explicitly cited events; then fill supporting primary excerpts.
	for _, c := range ids {
		if c.Kind == "event" {
			if err := addEvent(c.ID); err != nil {
				return ReviewBatchPacket{}, nil, 0, err
			}
		}
	}
	for _, c := range ids {
		if c.Kind != "finding" && c.Kind != "correlation" {
			continue
		}
		raw, err := s.store.BatchMemberJSON(p.CaseID, p.ID, c.Kind, c.ID)
		if err != nil {
			return ReviewBatchPacket{}, nil, 0, err
		}
		if c.Kind == "finding" && len(in.Findings) < narrative.DefaultLimits.MaxFindings {
			var f model.Finding
			if err = json.Unmarshal(raw, &f); err != nil {
				return ReviewBatchPacket{}, nil, 0, err
			}
			in.Findings = append(in.Findings, f)
			for _, id := range f.SupportingEvents {
				if err := addEvent(id); err != nil {
					return ReviewBatchPacket{}, nil, 0, err
				}
			}
		} else if c.Kind == "correlation" && len(in.Correlations) < narrative.ReviewMaxCorrelations {
			var cc model.Correlation
			if err = json.Unmarshal(raw, &cc); err != nil {
				return ReviewBatchPacket{}, nil, 0, err
			}
			in.Correlations = append(in.Correlations, cc)
			for _, id := range cc.EventIDs {
				if err := addEvent(id); err != nil {
					return ReviewBatchPacket{}, nil, 0, err
				}
			}
		}
	}
	sources, err := s.store.BatchMembers(p.CaseID, p.ID, "source", 0, store.BatchPageSize)
	if err != nil {
		return ReviewBatchPacket{}, nil, 0, err
	}
	for _, r := range sources {
		var sf model.SourceFile
		if err = json.Unmarshal([]byte(r.JSON), &sf); err != nil {
			return ReviewBatchPacket{}, nil, 0, err
		}
		in.Sources = append(in.Sources, sf)
	}
	prepared, omitted, err := narrative.PrepareReviewSynthesis(in, commentary)
	if err != nil {
		return ReviewBatchPacket{}, nil, omitted, err
	}
	narrative.AddBatchCatalog(prepared, p.Snapshot.Coverage, p.Snapshot.SourceParseGaps)
	if err := narrative.CheckReviewBatchSize(prepared); err != nil {
		return ReviewBatchPacket{}, nil, len(commentary), err
	}
	packet := ReviewBatchPacket{Seq: p.TotalBatches, Kind: "synthesis", State: "ready", Namespace: "synthesis", EventIDs: prepared.EventIDs, FindingIDs: prepared.FindingIDs, Privacy: prepared.Privacy, Coverage: prepared.Coverage, Payload: NarrativePayload{System: prepared.System, User: prepared.User, SHA256: payloadHash(prepared.System, prepared.User), Destination: p.Destination, Model: p.Model}}
	omittedBatches := map[int]bool{}
	for _, index := range prepared.SynthesisOmittedIndices {
		omittedBatches[origins[index]] = true
	}
	for seq := range omittedBatches {
		packet.OmittedSourceBatches = append(packet.OmittedSourceBatches, seq)
	}
	sort.Ints(packet.OmittedSourceBatches)
	for _, cc := range in.Correlations {
		packet.CorrelationIDs = append(packet.CorrelationIDs, cc.ID)
	}
	return packet, prepared, omitted, nil
}
