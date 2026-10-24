package store

// BatchProgress is calculated from persisted membership, never model prose.
type BatchProgress struct {
	Succeeded                int `json:"succeeded"`
	Failed                   int `json:"failed"`
	Cancelled                int `json:"cancelled"`
	Interrupted              int `json:"interrupted"`
	Unreviewed               int `json:"unreviewed"`
	Ready                    int `json:"ready"`
	Sending                  int `json:"sending"`
	PrimaryReviewedEvents    int `json:"primary_reviewed_events"`
	DistinctSuccessfulEvents int `json:"distinct_successful_events"`
	RequestsAttempted        int `json:"requests_attempted"`
	InputBytesAdmitted       int `json:"input_bytes_admitted"`
	OutputBytesRetained      int `json:"output_bytes_retained"`
}

func (s *Store) BatchProgress(caseID, runID string) (out BatchProgress, err error) {
	rows, err := s.db.Query(`SELECT state,count(*) FROM review_batch_packets WHERE case_id=? AND run_id=? AND json_extract(record_json,'$.kind')!='synthesis' GROUP BY state`, caseID, runID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var state string
		var n int
		if err = rows.Scan(&state, &n); err != nil {
			rows.Close()
			return out, err
		}
		switch state {
		case "succeeded":
			out.Succeeded = n
		case "failed":
			out.Failed = n
		case "cancelled":
			out.Cancelled = n
		case "interrupted":
			out.Interrupted = n
		case "unreviewed":
			out.Unreviewed = n
		case "ready":
			out.Ready = n
		case "sending":
			out.Sending = n
		}
	}
	out.Unreviewed += out.Ready
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	err = s.db.QueryRow(`SELECT count(DISTINCT m.member_id) FROM review_batch_members m JOIN review_batch_packets p ON p.case_id=m.case_id AND p.run_id=m.run_id AND json_extract(p.record_json,'$.kind')='event' AND m.ordinal>=json_extract(p.record_json,'$.offset') AND m.ordinal<json_extract(p.record_json,'$.offset')+json_extract(p.record_json,'$.primary_events') WHERE m.case_id=? AND m.run_id=? AND m.kind='event' AND p.state='succeeded'`, caseID, runID).Scan(&out.PrimaryReviewedEvents)
	if err != nil {
		return out, err
	}
	err = s.db.QueryRow(`SELECT count(DISTINCT m.member_id) FROM review_batch_packets p,json_each(p.record_json,'$.event_ids') e JOIN review_batch_members m ON m.case_id=p.case_id AND m.run_id=p.run_id AND m.kind='event' AND m.member_id=e.value WHERE p.case_id=? AND p.run_id=? AND p.state='succeeded' AND json_extract(p.record_json,'$.kind')!='synthesis'`, caseID, runID).Scan(&out.DistinctSuccessfulEvents)
	if err != nil {
		return out, err
	}
	err = s.db.QueryRow(`SELECT count(*),coalesce(sum(length(CAST(json_extract(record_json,'$.payload.system') AS BLOB))+length(CAST(json_extract(record_json,'$.payload.user') AS BLOB))),0),coalesce(sum(coalesce(json_extract(record_json,'$.output_bytes_retained'),0)),0) FROM review_batch_packets WHERE case_id=? AND run_id=? AND coalesce(json_extract(record_json,'$.attempted_at'),'')!=''`, caseID, runID).Scan(&out.RequestsAttempted, &out.InputBytesAdmitted, &out.OutputBytesRetained)
	return out, err
}
