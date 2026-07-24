package forensic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

func (c *Case) Activity(ctx context.Context, id ActivityID) (ActivityInfo, error) {
	var a ActivityInfo
	var session, parent sql.NullString
	var started string
	var finished, outcome, toolJSON, executionJSON, reportedStart, reportedEnd sql.NullString
	err := c.db.QueryRowContext(ctx, "SELECT id,session_id,agent_id,type,label,capture_mode,parent_activity_id,tool_json,config_digest,execution_json,time_source,reported_started_at,reported_finished_at,state,started_at,finished_at,outcome_json FROM activities WHERE id=?", id).Scan(&a.ID, &session, &a.Agent, &a.Type, &a.Label, &a.CaptureMode, &parent, &toolJSON, &a.ConfigDigest, &executionJSON, &a.TimeSource, &reportedStart, &reportedEnd, &a.State, &started, &finished, &outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, mapSQLError(err)
	}
	a.Session = SessionID(session.String)
	a.Parent = ActivityID(parent.String)
	if toolJSON.Valid && toolJSON.String != "null" {
		var tool ToolDescriptor
		if json.Unmarshal([]byte(toolJSON.String), &tool) != nil {
			return a, ErrIntegrity
		}
		a.Tool = &tool
	}
	if executionJSON.Valid && executionJSON.String != "null" {
		var execution ExecutionDescriptor
		if json.Unmarshal([]byte(executionJSON.String), &execution) != nil {
			return a, ErrIntegrity
		}
		a.Execution = &execution
	}
	if reportedStart.Valid {
		v, parseErr := time.Parse(time.RFC3339Nano, reportedStart.String)
		if parseErr != nil {
			return a, ErrIntegrity
		}
		a.ReportedStartedAt = &v
	}
	if reportedEnd.Valid {
		v, parseErr := time.Parse(time.RFC3339Nano, reportedEnd.String)
		if parseErr != nil {
			return a, ErrIntegrity
		}
		a.ReportedFinishedAt = &v
	}
	a.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	if finished.Valid {
		v, _ := time.Parse(time.RFC3339Nano, finished.String)
		a.FinishedAt = &v
	}
	if outcome.Valid {
		var v Outcome
		if json.Unmarshal([]byte(outcome.String), &v) == nil {
			a.Outcome = &v
		}
	}
	rows, err := c.db.QueryContext(ctx, "SELECT agent_id,role FROM activity_agents WHERE activity_id=? ORDER BY role,agent_id", id)
	if err != nil {
		return a, mapSQLError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var associated ActivityAgent
		if err = rows.Scan(&associated.Agent, &associated.Role); err != nil {
			return a, err
		}
		a.Agents = append(a.Agents, associated)
	}
	if err = rows.Err(); err != nil {
		return a, err
	}
	return a, nil
}

func (c *Case) Trace(ctx context.Context, root Entity) (ProvenanceGraph, error) {
	if root == nil {
		return ProvenanceGraph{}, ErrInvalid
	}
	rootRef := root.EntityRef()
	graph := ProvenanceGraph{Root: rootRef}
	seenEntities := map[string]bool{}
	seenActivities := map[ActivityID]bool{}
	queue := []EntityRef{rootRef}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return graph, err
		}
		entity := queue[0]
		queue = queue[1:]
		if seenEntities[entity.ID] {
			continue
		}
		seenEntities[entity.ID] = true
		var kind EntityKind
		var activity ActivityID
		err := c.db.QueryRowContext(ctx, "SELECT kind,generating_activity_id FROM entities WHERE id=?", entity.ID).Scan(&kind, &activity)
		if errors.Is(err, sql.ErrNoRows) {
			return graph, ErrNotFound
		}
		if err != nil {
			return graph, mapSQLError(err)
		}
		entity.Kind = kind
		graph.Entities = append(graph.Entities, entity)
		graph.Edges = append(graph.Edges, ProvenanceEdge{Activity: activity, Entity: entity, Direction: "generated", Role: outputRole(ctx, c.db, activity, entity.ID)})
		if !seenActivities[activity] {
			info, err := c.Activity(ctx, activity)
			if err != nil {
				return graph, err
			}
			seenActivities[activity] = true
			graph.Activities = append(graph.Activities, info)
			rows, err := c.db.QueryContext(ctx, "SELECT e.id,e.kind,i.role FROM activity_inputs i JOIN entities e ON e.id=i.entity_id WHERE i.activity_id=? ORDER BY e.kind,e.id,i.role", activity)
			if err != nil {
				return graph, err
			}
			for rows.Next() {
				var input EntityRef
				var role string
				if err = rows.Scan(&input.ID, &input.Kind, &role); err != nil {
					rows.Close()
					return graph, err
				}
				graph.Edges = append(graph.Edges, ProvenanceEdge{Activity: activity, Entity: input, Direction: "used", Role: role})
				queue = append(queue, input)
			}
			if err = rows.Close(); err != nil {
				return graph, err
			}
		}
	}
	sort.Slice(graph.Entities, func(i, j int) bool {
		if graph.Entities[i].Kind == graph.Entities[j].Kind {
			return graph.Entities[i].ID < graph.Entities[j].ID
		}
		return graph.Entities[i].Kind < graph.Entities[j].Kind
	})
	sort.Slice(graph.Activities, func(i, j int) bool { return graph.Activities[i].ID < graph.Activities[j].ID })
	return graph, nil
}

func outputRole(ctx context.Context, db *sql.DB, activity ActivityID, entity string) string {
	var role string
	_ = db.QueryRowContext(ctx, "SELECT role FROM activity_outputs WHERE activity_id=? AND entity_id=?", activity, entity).Scan(&role)
	return role
}
