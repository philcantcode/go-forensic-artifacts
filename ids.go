package forensic

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type CaseID string
type AgentID string
type SessionID string
type ActivityID string
type EvidenceID string
type TreeID string
type ObjectID string
type ArtifactID string
type AssertionID string
type FindingID string
type FindingRevisionID string
type SelectionID string
type ProjectionID string
type MaterializationID string
type DeliverableID string
type BlobRef string

func newID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	ms := uint64(time.Now().UTC().UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	return prefix + hex.EncodeToString(b[:]), nil
}

func validID(v, prefix string) bool {
	if !strings.HasPrefix(v, prefix) || len(v) != len(prefix)+32 {
		return false
	}
	b, err := hex.DecodeString(v[len(prefix):])
	return err == nil && len(b) == 16 && b[6]>>4 == 7 && b[8]>>6 == 2
}

func newCaseID() (CaseID, error)           { v, e := newID("case_"); return CaseID(v), e }
func newAgentID() (AgentID, error)         { v, e := newID("agt_"); return AgentID(v), e }
func newSessionID() (SessionID, error)     { v, e := newID("ses_"); return SessionID(v), e }
func newActivityID() (ActivityID, error)   { v, e := newID("act_"); return ActivityID(v), e }
func newEvidenceID() (EvidenceID, error)   { v, e := newID("evd_"); return EvidenceID(v), e }
func newTreeID() (TreeID, error)           { v, e := newID("tree_"); return TreeID(v), e }
func newObjectID() (ObjectID, error)       { v, e := newID("obj_"); return ObjectID(v), e }
func newArtifactID() (ArtifactID, error)   { v, e := newID("art_"); return ArtifactID(v), e }
func newAssertionID() (AssertionID, error) { v, e := newID("asn_"); return AssertionID(v), e }
func newFindingID() (FindingID, error)     { v, e := newID("fnd_"); return FindingID(v), e }
func newFindingRevisionID() (FindingRevisionID, error) {
	v, e := newID("fnd_")
	return FindingRevisionID(v), e
}
func newSelectionID() (SelectionID, error)   { v, e := newID("sel_"); return SelectionID(v), e }
func newProjectionID() (ProjectionID, error) { v, e := newID("prj_"); return ProjectionID(v), e }
func newMaterializationID() (MaterializationID, error) {
	v, e := newID("mat_")
	return MaterializationID(v), e
}
func newDeliverableID() (DeliverableID, error) { v, e := newID("dlv_"); return DeliverableID(v), e }
