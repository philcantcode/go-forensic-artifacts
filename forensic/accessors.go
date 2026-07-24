package forensic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Evidence loads immutable accession metadata and its root object.
func (c *Case) Evidence(ctx context.Context, id EvidenceID) (Evidence, error) {
	if err := c.checkOpen(); err != nil {
		return Evidence{}, err
	}
	var evidence Evidence
	var acquisitionJSON string
	err := c.db.QueryRowContext(ctx, `SELECT ev.id,ev.label,ev.acquisition_json,e.created_revision,o.id,o.blob_digest,o.size,oe.display_name,oe.media_type,o.path_display,oe.generating_activity_id,oe.created_revision FROM evidence ev JOIN entities e ON e.id=ev.id JOIN evidence_objects eo ON eo.evidence_id=ev.id AND eo.role='root' JOIN objects o ON o.id=eo.object_id JOIN entities oe ON oe.id=o.id WHERE ev.id=?`, id).Scan(&evidence.ID, &evidence.Label, &acquisitionJSON, &evidence.CreatedRevision, &evidence.RootObject.ID, &evidence.RootObject.Blob, &evidence.RootObject.Size, &evidence.RootObject.DisplayName, &evidence.RootObject.MediaType, &evidence.RootObject.Path, &evidence.RootObject.GeneratingActivity, &evidence.RootObject.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, ErrNotFound
	}
	if err != nil {
		return Evidence{}, mapSQLError(err)
	}
	if json.Unmarshal([]byte(acquisitionJSON), &evidence.Acquisition) != nil {
		return Evidence{}, ErrIntegrity
	}
	return evidence, nil
}

// Assertion loads an immutable relationship, tag, comment, correction, or
// review assertion and its exact targets.
func (c *Case) Assertion(ctx context.Context, id AssertionID) (AssertionRef, error) {
	if err := c.checkOpen(); err != nil {
		return AssertionRef{}, err
	}
	var assertion AssertionRef
	var confidence sql.NullFloat64
	var supersedes sql.NullString
	err := c.db.QueryRowContext(ctx, `SELECT a.id,a.assertion_type,a.body,a.confidence,a.supersedes_id,a.generating_activity_id,e.created_revision FROM assertions a JOIN entities e ON e.id=a.id WHERE a.id=?`, id).Scan(&assertion.ID, &assertion.Type, &assertion.Body, &confidence, &supersedes, &assertion.GeneratingActivity, &assertion.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return AssertionRef{}, ErrNotFound
	}
	if err != nil {
		return AssertionRef{}, mapSQLError(err)
	}
	if confidence.Valid {
		assertion.Confidence = &confidence.Float64
	}
	assertion.Supersedes = AssertionID(supersedes.String)
	rows, err := c.db.QueryContext(ctx, "SELECT target_id,target_kind FROM assertion_targets WHERE assertion_id=? ORDER BY target_kind,target_id", id)
	if err != nil {
		return AssertionRef{}, mapSQLError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var target EntityRef
		if err = rows.Scan(&target.ID, &target.Kind); err != nil {
			return AssertionRef{}, err
		}
		assertion.Targets = append(assertion.Targets, target)
	}
	return assertion, rows.Err()
}

// FindingRevision loads the exact immutable revision requested, including an
// older revision after the stable finding has advanced.
func (c *Case) FindingRevision(ctx context.Context, id FindingRevisionID) (FindingRef, error) {
	if err := c.checkOpen(); err != nil {
		return FindingRef{}, err
	}
	var finding FindingRef
	var confidence sql.NullFloat64
	var assigneesJSON string
	var vulnerabilityJSON sql.NullString
	err := c.db.QueryRowContext(ctx, `SELECT f.id,r.id,r.version,f.title,r.body,r.status,r.confidence,r.severity,r.review_state,r.assignees_json,r.vulnerability_json,e.created_revision FROM finding_revisions r JOIN findings f ON f.id=r.finding_id JOIN entities e ON e.id=r.id WHERE r.id=?`, id).Scan(&finding.ID, &finding.Current, &finding.Version, &finding.Title, &finding.Body, &finding.Status, &confidence, &finding.Severity, &finding.ReviewState, &assigneesJSON, &vulnerabilityJSON, &finding.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return FindingRef{}, ErrNotFound
	}
	if err != nil {
		return FindingRef{}, mapSQLError(err)
	}
	if confidence.Valid {
		finding.Confidence = &confidence.Float64
	}
	if json.Unmarshal([]byte(assigneesJSON), &finding.Assignees) != nil {
		return FindingRef{}, ErrIntegrity
	}
	if vulnerabilityJSON.Valid && vulnerabilityJSON.String != "null" {
		var vulnerability VulnerabilityDetails
		if json.Unmarshal([]byte(vulnerabilityJSON.String), &vulnerability) != nil {
			return FindingRef{}, ErrIntegrity
		}
		finding.Vulnerability = &vulnerability
	}
	return finding, nil
}
