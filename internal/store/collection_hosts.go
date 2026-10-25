package store

import "fmt"

// CollectionHosts returns distinct recorded hosts from this collection and its
// recollection observations, not every full event in the case. A large census
// fails explicitly rather than guessing a host from a truncated prefix.
func (s *Store) CollectionHosts(caseID, collectionID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT host FROM events WHERE case_id=? AND collection_id=? AND TRIM(host)<>''
 UNION SELECT e.host FROM event_observations o JOIN events e ON e.id=o.event_id
 JOIN source_files sf ON sf.id=o.source_file_id AND sf.collection_id=o.collection_id AND sf.case_id=o.case_id AND sf.deleted_at=''
 WHERE o.case_id=? AND e.case_id=? AND o.collection_id=? AND TRIM(e.host)<>''
 ORDER BY host LIMIT 4097`, caseID, collectionID, caseID, caseID, collectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
		if len(hosts) > 4096 {
			return nil, fmt.Errorf("collection host census exceeds 4096 distinct names; host enrichment stopped")
		}
	}
	return hosts, rows.Err()
}
