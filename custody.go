package forensic

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RecordCustodyTransfer records custody as an activity over an existing item.
// It intentionally creates no replacement evidence or byte object: custody is
// an event about possession/location, not a derivation.
func (s *Session) RecordCustodyTransfer(ctx context.Context, spec CustodyTransferSpec) (CustodyEvent, error) {
	if err := s.checkOpen(); err != nil {
		return CustodyEvent{}, err
	}
	if spec.Item.ID == "" || spec.OccurredAt.IsZero() {
		return CustodyEvent{}, fmt.Errorf("%w: custody item and occurred time required", ErrInvalid)
	}
	if spec.FromAgent == "" && spec.ToAgent == "" && strings.TrimSpace(spec.FromLocation) == "" && strings.TrimSpace(spec.ToLocation) == "" {
		return CustodyEvent{}, fmt.Errorf("%w: custody transfer requires an agent or location endpoint", ErrInvalid)
	}
	spec.OccurredAt = spec.OccurredAt.UTC()
	fingerprint, configJSON, err := digestJSON(spec)
	if err != nil {
		return CustodyEvent{}, err
	}
	activityID, err := newActivityID()
	if err != nil {
		return CustodyEvent{}, err
	}
	result := CustodyEvent{
		Activity: activityID, Item: spec.Item, FromAgent: spec.FromAgent, ToAgent: spec.ToAgent,
		FromLocation: spec.FromLocation, ToLocation: spec.ToLocation, Purpose: spec.Purpose,
		ReferenceNumber: spec.ReferenceNumber, OccurredAt: spec.OccurredAt,
		Acknowledgement: spec.Acknowledgement, Signature: append([]byte(nil), spec.Signature...),
	}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "custody.transfer", fingerprint, []string{string(activityID), spec.Item.ID}, func(tx *sql.Tx, revision int64) error {
		if spec.IdempotencyKey != "" {
			var old CustodyEvent
			found, lookupErr := lookupIdempotency(ctx, tx, string(s.ID()), "custody.transfer", spec.IdempotencyKey, fingerprint, &old)
			if lookupErr != nil {
				return lookupErr
			}
			if found {
				result = old
				return errIdempotentReplay
			}
		}
		var actualKind EntityKind
		if queryErr := tx.QueryRowContext(ctx, "SELECT kind FROM entities WHERE id=?", spec.Item.ID).Scan(&actualKind); errors.Is(queryErr, sql.ErrNoRows) {
			return ErrNotFound
		} else if queryErr != nil {
			return queryErr
		}
		if spec.Item.Kind != "" && actualKind != spec.Item.Kind {
			return fmt.Errorf("%w: custody item kind does not match catalog", ErrInvalid)
		}
		result.Item.Kind = actualKind
		for _, agent := range []AgentID{spec.FromAgent, spec.ToAgent} {
			if agent == "" {
				continue
			}
			var count int
			if queryErr := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE id=?", agent).Scan(&count); queryErr != nil {
				return queryErr
			} else if count != 1 {
				return ErrNotFound
			}
		}
		now := time.Now().UTC()
		nowText := now.Format(time.RFC3339Nano)
		outcomeJSON, _ := canonicalJSON(OutcomeSucceeded())
		if _, execErr := tx.ExecContext(ctx, `INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)`, activityID, s.ID(), s.info.Agent.ID, ActivityCustodyTransfer, "Transfer custody of "+spec.Item.ID, string(configJSON), fingerprint, CaptureReported, ActivitySucceeded, revision, nowText, nowText, string(outcomeJSON), spec.IdempotencyKey); execErr != nil {
			return execErr
		}
		if _, execErr := tx.ExecContext(ctx, "INSERT INTO activity_agents(activity_id,agent_id,role) VALUES(?,?,'recorder')", activityID, s.info.Agent.ID); execErr != nil {
			return execErr
		}
		if spec.FromAgent != "" {
			if _, execErr := tx.ExecContext(ctx, "INSERT OR IGNORE INTO activity_agents(activity_id,agent_id,role) VALUES(?,?,'custodian-from')", activityID, spec.FromAgent); execErr != nil {
				return execErr
			}
		}
		if spec.ToAgent != "" {
			if _, execErr := tx.ExecContext(ctx, "INSERT OR IGNORE INTO activity_agents(activity_id,agent_id,role) VALUES(?,?,'custodian-to')", activityID, spec.ToAgent); execErr != nil {
				return execErr
			}
		}
		if _, execErr := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'custody-item')", activityID, spec.Item.ID); execErr != nil {
			return execErr
		}
		acknowledgementJSON, _ := canonicalJSON(spec.Acknowledgement)
		if _, execErr := tx.ExecContext(ctx, `INSERT INTO custody_events(activity_id,item_entity_id,from_agent_id,to_agent_id,from_location,to_location,purpose,reference_number,occurred_at,recorded_at,acknowledgement_json,signature,created_revision) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, activityID, spec.Item.ID, nullString(string(spec.FromAgent)), nullString(string(spec.ToAgent)), spec.FromLocation, spec.ToLocation, spec.Purpose, spec.ReferenceNumber, spec.OccurredAt.Format(time.RFC3339Nano), nowText, string(acknowledgementJSON), nullBytes(spec.Signature), revision); execErr != nil {
			return execErr
		}
		result.RecordedAt = now
		result.CreatedRevision = revision
		return storeIdempotency(ctx, tx, string(s.ID()), "custody.transfer", spec.IdempotencyKey, fingerprint, result)
	})
	return result, err
}

// CustodyEvents returns the append-only custody history for an entity.
func (c *Case) CustodyEvents(ctx context.Context, item EntityRef) ([]CustodyEvent, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if item.ID == "" {
		return nil, fmt.Errorf("%w: custody item required", ErrInvalid)
	}
	rows, err := c.db.QueryContext(ctx, `SELECT ce.activity_id,e.kind,COALESCE(ce.from_agent_id,''),COALESCE(ce.to_agent_id,''),ce.from_location,ce.to_location,ce.purpose,ce.reference_number,ce.occurred_at,ce.recorded_at,ce.acknowledgement_json,ce.signature,ce.created_revision FROM custody_events ce JOIN entities e ON e.id=ce.item_entity_id WHERE ce.item_entity_id=? ORDER BY ce.occurred_at,ce.activity_id`, item.ID)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var events []CustodyEvent
	for rows.Next() {
		var event CustodyEvent
		var occurred, recorded, acknowledgementJSON string
		var signature []byte
		event.Item.ID = item.ID
		if err = rows.Scan(&event.Activity, &event.Item.Kind, &event.FromAgent, &event.ToAgent, &event.FromLocation, &event.ToLocation, &event.Purpose, &event.ReferenceNumber, &occurred, &recorded, &acknowledgementJSON, &signature, &event.CreatedRevision); err != nil {
			return nil, err
		}
		if event.OccurredAt, err = time.Parse(time.RFC3339Nano, occurred); err != nil {
			return nil, ErrIntegrity
		}
		if event.RecordedAt, err = time.Parse(time.RFC3339Nano, recorded); err != nil {
			return nil, ErrIntegrity
		}
		if acknowledgementJSON != "" && acknowledgementJSON != "null" {
			decoder := json.NewDecoder(bytes.NewBufferString(acknowledgementJSON))
			decoder.UseNumber()
			if decoder.Decode(&event.Acknowledgement) != nil {
				return nil, ErrIntegrity
			}
		}
		event.Signature = append([]byte(nil), signature...)
		events = append(events, event)
	}
	return events, rows.Err()
}

func nullBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
