package api

import (
	"context"
	"encoding/json"
	"sync"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// Keep only one case's derived models, never evidence/detail bodies. Serialized
// storage both bounds retained bytes and makes every caller own its arrays.
const investigationCacheBytes = 4 << 20
const investigationCacheFlights = 8

type investigationModelFlight struct {
	done   chan struct{}
	models []byte // immutable; held only by already-waiting requests
	token  store.ChangeToken
}

type investigationModelCache struct {
	mu      sync.Mutex
	caseID  string
	token   store.ChangeToken
	models  []byte
	flights map[string]*investigationModelFlight
	changed chan struct{}
}

func (c *investigationModelCache) get(ctx context.Context, caseID string, revision func(context.Context) (store.ChangeToken, error), build func() ([]model.Investigation, error)) ([]model.Investigation, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := revision(ctx)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.models != nil && c.caseID == caseID && c.token == token {
			data := c.models
			c.mu.Unlock()
			var out []model.Investigation
			err = json.Unmarshal(data, &out)
			if err == nil {
				err = ctx.Err()
			}
			return out, err
		}
		if flight := c.flights[caseID]; flight != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-flight.done:
				// Deliver the completed flight even if another case evicted the
				// single cache entry, or these models exceed the retention cap.
				// Revalidate: a write may have committed while this waiter slept.
				if flight.models != nil {
					now, err := revision(ctx)
					if err != nil {
						return nil, err
					}
					if now == flight.token {
						var out []model.Investigation
						err = json.Unmarshal(flight.models, &out)
						if err == nil {
							err = ctx.Err()
						}
						return out, err
					}
				}
				continue
			}
		}
		// Bound even the number of retained cold-case keys. Waiting callers hold
		// no cache mutex; unrelated cases can compute independently up to this cap.
		if len(c.flights) >= investigationCacheFlights {
			changed := c.changed
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		if c.flights == nil {
			c.flights = make(map[string]*investigationModelFlight)
		}
		if c.changed == nil {
			c.changed = make(chan struct{})
		}
		flight := &investigationModelFlight{done: make(chan struct{})}
		c.flights[caseID] = flight
		c.mu.Unlock()

		// The leader owns its request context. Cancelled/failed leaders publish
		// nothing; waiters retry with their own context, not the leader's error.
		out, err := build()
		var data []byte
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			after, e := revision(ctx)
			if e != nil {
				err = e
			} else if after == token {
				data, err = json.Marshal(out)
			}
		}
		c.mu.Lock()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil && len(data) > 0 {
			flight.models, flight.token = data, token
			if len(data) <= investigationCacheBytes {
				c.caseID, c.token, c.models = caseID, token, data
			}
		}
		delete(c.flights, caseID)
		close(flight.done)
		close(c.changed)
		c.changed = make(chan struct{})
		c.mu.Unlock()
		return out, err
	}
}
