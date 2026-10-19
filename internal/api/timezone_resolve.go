package api

import (
	"fmt"
	"log/slog"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/regf"
	"tracefall/internal/timezone"
)

// resolveCollectionTimeZone reads the host time zone from the SYSTEM hive of
// this collection and records it on the collection. It runs once per
// collection: a result, or the reason there is none, is kept, so later
// imports do not reopen the hive.
//
// It only ever reads the collection's own hive. A zone is never taken from
// another collection or from the server's clock, because the report would
// then state a zone the evidence does not hold.
func (s *Service) resolveCollectionTimeZone(caseID, collectionID string, collection model.Collection) (model.TimeZoneBasis, error) {
	if collection.TimeZone.Recorded || collection.TimeZone.Reason != "" {
		return collection.TimeZone, nil
	}
	tz := s.readCollectionTimeZone(caseID, collectionID, collection)
	if err := s.store.SetCollectionTimeZone(collectionID, tz); err != nil {
		return tz, fmt.Errorf("recording the host time zone: %w", err)
	}
	return tz, nil
}

func (s *Service) readCollectionTimeZone(caseID, collectionID string, collection model.Collection) model.TimeZoneBasis {
	candidates, err := s.systemHiveCandidates(caseID, collectionID)
	if err != nil {
		return model.TimeZoneBasis{Reason: fmt.Sprintf("the collection's SYSTEM hive could not be listed: %v", err)}
	}
	if len(candidates) == 0 {
		return model.TimeZoneBasis{Reason: "no SYSTEM hive in this collection, so local-time registry readings are not converted to UTC"}
	}
	reason := "the SYSTEM hive could not be read"
	for _, sf := range candidates {
		path, ok := s.materializeForRead(caseID, collectionID, collection, sf)
		if !ok {
			continue
		}
		h, err := regf.Open(path, regf.DefaultLimits())
		if err != nil {
			reason = fmt.Sprintf("%s could not be read as a registry hive", sf.Path)
			continue
		}
		b := timezone.FromSystemHive(h)
		h.Close()
		if b.Recorded {
			return model.TimeZoneBasis{
				Recorded:          true,
				KeyName:           b.KeyName,
				ActiveBiasMinutes: b.ActiveBiasMinutes,
				ValueUsed:         b.ValueUsed,
				ControlSet:        b.ControlSet,
				Source:            fmt.Sprintf("SYSTEM hive %s, %s\\TimeZoneInformation %s", sf.Path, b.ControlSet, b.ValueUsed),
			}
		}
		reason = b.Reason
	}
	return model.TimeZoneBasis{Reason: reason}
}

// collectionTimeZoneForParse is the basis the parsers of a collection see:
// nil when none is recorded, so parsers keep local readings as they are.
func collectionTimeZoneForParse(tz model.TimeZoneBasis) *parsers.TimeBasis {
	if !tz.Recorded {
		return nil
	}
	return &parsers.TimeBasis{ActiveBiasMinutes: tz.ActiveBiasMinutes, Source: tz.Source}
}

// logTimeZoneFailure keeps a store failure visible without stopping the
// import: the import still runs, without a zone, and the report says so.
func logTimeZoneFailure(caseID, collectionID string, err error) {
	if err != nil {
		slog.Warn("import: host time zone not recorded", "case", caseID, "collection", collectionID, "error", err)
	}
}
