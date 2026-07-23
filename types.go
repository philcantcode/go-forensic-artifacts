package forensic

import (
	"context"
	"crypto"
	"io"
	"time"
)

const (
	RepositoryFormat = 1
	CaseFormat       = 1
	SchemaVersion    = 1
)

type AgentKind string

const (
	AgentHuman        AgentKind = "human"
	AgentSoftware     AgentKind = "software"
	AgentService      AgentKind = "service"
	AgentOrganization AgentKind = "organization"
	AgentUnknown      AgentKind = "unknown"
)

type Config struct {
	Root         string
	DefaultAgent AgentSpec
	BusyTimeout  time.Duration
}

type AgentSpec struct {
	Kind AgentKind `json:"kind"`
	Name string    `json:"name"`
}
type AgentRef struct {
	ID   AgentID   `json:"id"`
	Kind AgentKind `json:"kind"`
	Name string    `json:"name"`
}
type CaseSpec struct {
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	IdempotencyKey string `json:"-"`
}
type CaseInfo struct {
	ID          CaseID    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Revision    int64     `json:"revision"`
}

type CaseSelector struct {
	id   CaseID
	name string
}

func ByID(id CaseID) CaseSelector     { return CaseSelector{id: id} }
func ByName(name string) CaseSelector { return CaseSelector{name: name} }

type SessionSpec struct {
	Agent          AgentRef `json:"agent"`
	Label          string   `json:"label"`
	IdempotencyKey string   `json:"-"`
}
type SessionInfo struct {
	ID        SessionID  `json:"id"`
	Agent     AgentRef   `json:"agent"`
	Label     string     `json:"label"`
	StartedAt time.Time  `json:"started_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
}

type ActivityType string

const (
	ActivityCaseCreate            ActivityType = "case.create"
	ActivityEvidenceAccession     ActivityType = "evidence.accession"
	ActivityImport                ActivityType = "object.import"
	ActivityExtract               ActivityType = "object.extract"
	ActivityParse                 ActivityType = "artifact.parse"
	ActivitySearch                ActivityType = "entity.search"
	ActivityFindingAuthor         ActivityType = "finding.author"
	ActivityFindingReview         ActivityType = "finding.review"
	ActivitySelectionFreeze       ActivityType = "selection.freeze"
	ActivityProjectionCreate      ActivityType = "projection.create"
	ActivityProjectionMaterialize ActivityType = "projection.materialize"
	ActivityExperiment            ActivityType = "experiment.execute"
	ActivityAssertionRecord       ActivityType = "assertion.record"
	ActivityDeliverablePackage    ActivityType = "deliverable.package"
	ActivityIntegrityVerify       ActivityType = "integrity.verify"
)

type CaptureMode string

const (
	CaptureLibrary  CaptureMode = "library"
	CaptureWrapped  CaptureMode = "wrapped"
	CaptureReported CaptureMode = "reported"
	CaptureImported CaptureMode = "imported"
)

type ToolDescriptor struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	BuildDigest string `json:"build_digest,omitempty"`
	URI         string `json:"uri,omitempty"`
}
type ActivitySpec struct {
	Type           ActivityType    `json:"type"`
	Label          string          `json:"label"`
	Tool           *ToolDescriptor `json:"tool,omitempty"`
	Config         map[string]any  `json:"config,omitempty"`
	CaptureMode    CaptureMode     `json:"capture_mode,omitempty"`
	IdempotencyKey string          `json:"-"`
}
type ActivityState string

const (
	ActivityRunning     ActivityState = "running"
	ActivitySucceeded   ActivityState = "succeeded"
	ActivityFailed      ActivityState = "failed"
	ActivityCancelled   ActivityState = "cancelled"
	ActivityInterrupted ActivityState = "interrupted"
)

type Outcome struct {
	State    ActivityState `json:"state"`
	Summary  string        `json:"summary,omitempty"`
	ExitCode *int          `json:"exit_code,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

func OutcomeSucceeded() Outcome { return Outcome{State: ActivitySucceeded} }
func OutcomeFailed(err error) Outcome {
	o := Outcome{State: ActivityFailed}
	if err != nil {
		o.Summary = err.Error()
	}
	return o
}
func OutcomeCancelled() Outcome { return Outcome{State: ActivityCancelled} }

type EntityKind string

const (
	EntityEvidence        EntityKind = "evidence"
	EntitySourceTree      EntityKind = "source_tree"
	EntityObject          EntityKind = "object"
	EntityArtifact        EntityKind = "artifact"
	EntityAssertion       EntityKind = "assertion"
	EntityFindingRevision EntityKind = "finding_revision"
	EntitySelection       EntityKind = "selection"
	EntityProjection      EntityKind = "projection"
	EntityManifest        EntityKind = "manifest"
	EntityDeliverable     EntityKind = "deliverable"
)

type EntityRef struct {
	ID   string     `json:"id"`
	Kind EntityKind `json:"kind"`
}
type Entity interface{ EntityRef() EntityRef }

func (e EntityRef) EntityRef() EntityRef { return e }

type AcquisitionSpec struct {
	Method         string            `json:"method"`
	SourceURI      string            `json:"source_uri,omitempty"`
	Custodian      string            `json:"custodian,omitempty"`
	SuppliedHashes map[string]string `json:"supplied_hashes,omitempty"`
}
type EvidenceSpec struct {
	Label          string          `json:"label"`
	Acquisition    AcquisitionSpec `json:"acquisition"`
	IdempotencyKey string          `json:"-"`
}
type Evidence struct {
	ID              EvidenceID      `json:"id"`
	Label           string          `json:"label"`
	Acquisition     AcquisitionSpec `json:"acquisition"`
	RootObject      ObjectRef       `json:"root_object"`
	CreatedRevision int64           `json:"created_revision"`
}

func (e Evidence) EntityRef() EntityRef { return EntityRef{ID: string(e.ID), Kind: EntityEvidence} }

type SourceTreeSpec struct {
	Label          string          `json:"label"`
	Acquisition    AcquisitionSpec `json:"acquisition"`
	IncludeGitDir  bool            `json:"include_git_dir"`
	IdempotencyKey string          `json:"-"`
}

type TreeEntryKind string

const (
	TreeEntryFile      TreeEntryKind = "file"
	TreeEntryDirectory TreeEntryKind = "directory"
	TreeEntrySymlink   TreeEntryKind = "symlink"
)

type TreeEntry struct {
	Path       string        `json:"path"`
	Kind       TreeEntryKind `json:"kind"`
	Mode       uint32        `json:"mode"`
	Size       int64         `json:"size,omitempty"`
	SHA256     string        `json:"sha256,omitempty"`
	LinkTarget string        `json:"link_target,omitempty"`
	Object     *ObjectRef    `json:"object,omitempty"`
}

type SourceTree struct {
	ID              TreeID      `json:"id"`
	Evidence        EvidenceID  `json:"evidence"`
	Label           string      `json:"label"`
	TreeDigest      string      `json:"tree_digest"`
	Manifest        ObjectRef   `json:"manifest"`
	FileCount       int         `json:"file_count"`
	TotalBytes      int64       `json:"total_bytes"`
	Entries         []TreeEntry `json:"entries,omitempty"`
	CreatedRevision int64       `json:"created_revision"`
}

func (t SourceTree) EntityRef() EntityRef {
	return EntityRef{ID: string(t.ID), Kind: EntitySourceTree}
}

type LocatorType string

const (
	LocatorPath   LocatorType = "path"
	LocatorExtent LocatorType = "extent"
	LocatorJSON   LocatorType = "json"
	LocatorCustom LocatorType = "custom"
)

type SourceLocator interface{ LocatorType() LocatorType }
type PathLocator struct {
	Raw           []byte `json:"raw,omitempty"`
	Display       string `json:"display"`
	Encoding      string `json:"encoding,omitempty"`
	Separator     string `json:"separator,omitempty"`
	CaseSensitive *bool  `json:"case_sensitive,omitempty"`
}

func (PathLocator) LocatorType() LocatorType { return LocatorPath }

type ExtentLocator struct {
	Parent ObjectID `json:"parent"`
	Offset int64    `json:"offset"`
	Length int64    `json:"length"`
}

func (ExtentLocator) LocatorType() LocatorType { return LocatorExtent }

type JSONLocator struct {
	Object  ObjectID `json:"object"`
	Pointer string   `json:"pointer"`
}

func (JSONLocator) LocatorType() LocatorType { return LocatorJSON }

type CustomLocator struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

func (CustomLocator) LocatorType() LocatorType { return LocatorCustom }

type ObjectSpec struct {
	Role           string        `json:"role"`
	DisplayName    string        `json:"display_name"`
	MediaType      string        `json:"media_type,omitempty"`
	Source         SourceLocator `json:"-"`
	IdempotencyKey string        `json:"-"`
}
type ObjectRef struct {
	ID                 ObjectID   `json:"id"`
	Blob               BlobRef    `json:"blob"`
	Size               int64      `json:"size"`
	DisplayName        string     `json:"display_name"`
	MediaType          string     `json:"media_type,omitempty"`
	Path               string     `json:"path,omitempty"`
	GeneratingActivity ActivityID `json:"generating_activity"`
	CreatedRevision    int64      `json:"created_revision"`
}

func (o ObjectRef) EntityRef() EntityRef { return EntityRef{ID: string(o.ID), Kind: EntityObject} }

type ValueType string

const (
	ValueString      ValueType = "string"
	ValueInteger     ValueType = "integer"
	ValueUnsigned    ValueType = "unsigned"
	ValueReal        ValueType = "real"
	ValueBoolean     ValueType = "boolean"
	ValueBytes       ValueType = "bytes"
	ValueTime        ValueType = "time"
	ValueDuration    ValueType = "duration"
	ValueURI         ValueType = "uri"
	ValueJSON        ValueType = "json"
	ValueObjectRef   ValueType = "object_ref"
	ValueArtifactRef ValueType = "artifact_ref"
	ValueNull        ValueType = "null"
)

type ArtifactValue struct {
	Property   string        `json:"property"`
	Type       ValueType     `json:"type"`
	Raw        string        `json:"raw,omitempty"`
	Normalized any           `json:"normalized,omitempty"`
	Unit       string        `json:"unit,omitempty"`
	Language   string        `json:"language,omitempty"`
	Confidence *float64      `json:"confidence,omitempty"`
	Ordinal    int           `json:"ordinal,omitempty"`
	Source     SourceLocator `json:"-"`
}
type ArtifactDraft struct {
	Type        string          `json:"type"`
	DisplayName string          `json:"display_name,omitempty"`
	Source      ObjectID        `json:"source"`
	Values      []ArtifactValue `json:"values"`
}
type ArtifactRef struct {
	ID                 ArtifactID      `json:"id"`
	Type               string          `json:"type"`
	DisplayName        string          `json:"display_name,omitempty"`
	Source             ObjectID        `json:"source"`
	GeneratingActivity ActivityID      `json:"generating_activity"`
	CreatedRevision    int64           `json:"created_revision"`
	Values             []ArtifactValue `json:"values,omitempty"`
}

func (a ArtifactRef) EntityRef() EntityRef { return EntityRef{ID: string(a.ID), Kind: EntityArtifact} }

type ProducerKey string

type AssertionSpec struct {
	Type           string      `json:"type"`
	Body           string      `json:"body"`
	Targets        []EntityRef `json:"targets"`
	Confidence     *float64    `json:"confidence,omitempty"`
	Supersedes     AssertionID `json:"supersedes,omitempty"`
	IdempotencyKey string      `json:"-"`
}
type AssertionRef struct {
	ID                 AssertionID `json:"id"`
	Type               string      `json:"type"`
	Body               string      `json:"body"`
	Targets            []EntityRef `json:"targets"`
	GeneratingActivity ActivityID  `json:"generating_activity"`
	CreatedRevision    int64       `json:"created_revision"`
}

func (a AssertionRef) EntityRef() EntityRef {
	return EntityRef{ID: string(a.ID), Kind: EntityAssertion}
}

type FindingStatus string

const (
	FindingDraft     FindingStatus = "draft"
	FindingConfirmed FindingStatus = "confirmed"
	FindingRejected  FindingStatus = "rejected"
	FindingResolved  FindingStatus = "resolved"
)

type FindingSpec struct {
	Title          string                 `json:"title"`
	Body           string                 `json:"body"`
	Status         FindingStatus          `json:"status"`
	Confidence     *float64               `json:"confidence,omitempty"`
	Severity       string                 `json:"severity,omitempty"`
	Members        map[string][]EntityRef `json:"members,omitempty"`
	IdempotencyKey string                 `json:"-"`
}
type FindingRevisionSpec struct {
	ExpectedRevision FindingRevisionID      `json:"expected_revision"`
	Body             string                 `json:"body"`
	Status           FindingStatus          `json:"status"`
	Confidence       *float64               `json:"confidence,omitempty"`
	Severity         string                 `json:"severity,omitempty"`
	Members          map[string][]EntityRef `json:"members,omitempty"`
	IdempotencyKey   string                 `json:"-"`
}
type FindingRef struct {
	ID              FindingID         `json:"id"`
	Current         FindingRevisionID `json:"current_revision"`
	Version         int               `json:"version"`
	Title           string            `json:"title"`
	Body            string            `json:"body"`
	Status          FindingStatus     `json:"status"`
	Severity        string            `json:"severity,omitempty"`
	CreatedRevision int64             `json:"created_revision"`
}

func (f FindingRef) EntityRef() EntityRef {
	return EntityRef{ID: string(f.Current), Kind: EntityFindingRevision}
}

type QueryOp string

const (
	QueryAll          QueryOp = "all"
	QueryAnd          QueryOp = "and"
	QueryOr           QueryOp = "or"
	QueryNot          QueryOp = "not"
	QueryKind         QueryOp = "kind"
	QueryID           QueryOp = "id"
	QueryPathGlob     QueryOp = "path_glob"
	QueryHash         QueryOp = "hash"
	QueryActivity     QueryOp = "activity"
	QuerySession      QueryOp = "session"
	QueryArtifactType QueryOp = "artifact_type"
	QueryValue        QueryOp = "value"
	QuerySelection    QueryOp = "selection"
	QueryTree         QueryOp = "tree"
)

type Query struct {
	Op       QueryOp `json:"op"`
	Children []Query `json:"children,omitempty"`
	Value    string  `json:"value,omitempty"`
	Property string  `json:"property,omitempty"`
}

func All() Query                             { return Query{Op: QueryAll} }
func And(q ...Query) Query                   { return Query{Op: QueryAnd, Children: append([]Query(nil), q...)} }
func Or(q ...Query) Query                    { return Query{Op: QueryOr, Children: append([]Query(nil), q...)} }
func Not(q Query) Query                      { return Query{Op: QueryNot, Children: []Query{q}} }
func KindIs(k EntityKind) Query              { return Query{Op: QueryKind, Value: string(k)} }
func IDIs(id string) Query                   { return Query{Op: QueryID, Value: id} }
func PathGlob(pattern string) Query          { return Query{Op: QueryPathGlob, Value: pattern} }
func HashIs(hash BlobRef) Query              { return Query{Op: QueryHash, Value: string(hash)} }
func ProducedByActivity(id ActivityID) Query { return Query{Op: QueryActivity, Value: string(id)} }
func ProducedBySession(id SessionID) Query   { return Query{Op: QuerySession, Value: string(id)} }
func ArtifactTypeIs(t string) Query          { return Query{Op: QueryArtifactType, Value: t} }
func ValueEquals(property, value string) Query {
	return Query{Op: QueryValue, Property: property, Value: value}
}
func InSelection(id SelectionID) Query { return Query{Op: QuerySelection, Value: string(id)} }
func InTree(id TreeID) Query           { return Query{Op: QueryTree, Value: string(id)} }

type QueryResult struct {
	Revision int64       `json:"revision"`
	Entities []EntityRef `json:"entities"`
}
type FreezeSpec struct {
	Name           string `json:"name"`
	Query          Query  `json:"query"`
	IdempotencyKey string `json:"-"`
}
type Selection struct {
	ID              SelectionID `json:"id"`
	Name            string      `json:"name"`
	Revision        int64       `json:"revision"`
	Query           Query       `json:"query"`
	Members         []EntityRef `json:"members"`
	CreatedRevision int64       `json:"created_revision"`
}

func (s Selection) EntityRef() EntityRef { return EntityRef{ID: string(s.ID), Kind: EntitySelection} }

type ClosurePolicy string

const (
	ClosureExact          ClosurePolicy = "exact"
	ClosureSources        ClosurePolicy = "sources"
	ClosureInputBytes     ClosurePolicy = "input-bytes"
	ClosureFullProvenance ClosurePolicy = "full-provenance"
	ClosureFindingContext ClosurePolicy = "finding-context"
)

type Layout string

const (
	LayoutByID           Layout = "by-id"
	LayoutByEvidencePath Layout = "by-evidence"
	LayoutFlat           Layout = "flat"
)

type Include uint32

const (
	IncludeBytes Include = 1 << iota
	IncludeMetadata
	IncludeProvenance
	IncludeFindings
)

type ProjectionSpec struct {
	Selection      SelectionID   `json:"selection"`
	Closure        ClosurePolicy `json:"closure"`
	Layout         Layout        `json:"layout"`
	Include        Include       `json:"include"`
	IdempotencyKey string        `json:"-"`
}
type Projection struct {
	ID              ProjectionID   `json:"id"`
	Spec            ProjectionSpec `json:"spec"`
	Members         []EntityRef    `json:"members"`
	Digest          string         `json:"digest"`
	CreatedRevision int64          `json:"created_revision"`
}

func (p Projection) EntityRef() EntityRef { return EntityRef{ID: string(p.ID), Kind: EntityProjection} }

type DirectoryTarget struct {
	Path     string `json:"path"`
	Writable bool   `json:"writable"`
}
type ManifestEntry struct {
	Entity EntityRef `json:"entity"`
	Blob   BlobRef   `json:"blob,omitempty"`
	Size   int64     `json:"size,omitempty"`
	Path   string    `json:"path,omitempty"`
	SHA256 string    `json:"sha256,omitempty"`
	Reason string    `json:"reason"`
}
type ProjectionManifest struct {
	Format     int             `json:"format"`
	Case       CaseID          `json:"case"`
	Projection ProjectionID    `json:"projection"`
	Selection  SelectionID     `json:"selection"`
	Revision   int64           `json:"revision"`
	SpecDigest string          `json:"spec_digest"`
	Entries    []ManifestEntry `json:"entries"`
	Files      []ManifestFile  `json:"files,omitempty"`
}
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Role   string `json:"role"`
}
type Materialization struct {
	ID              MaterializationID `json:"id"`
	Projection      ProjectionID      `json:"projection"`
	Destination     string            `json:"destination"`
	Manifest        ObjectRef         `json:"manifest"`
	CreatedRevision int64             `json:"created_revision"`
}

type VerifyMode string

const (
	VerifyQuick      VerifyMode = "quick"
	VerifyOriginals  VerifyMode = "originals"
	VerifyFull       VerifyMode = "full"
	VerifyProjection VerifyMode = "projection"
)

type VerifySpec struct {
	Mode            VerifyMode
	Materialization MaterializationID
}
type VerifyIssue struct {
	Code   string    `json:"code"`
	Path   string    `json:"path,omitempty"`
	Entity EntityRef `json:"entity,omitempty"`
	Detail string    `json:"detail"`
}
type VerifyReport struct {
	Mode         VerifyMode    `json:"mode"`
	Case         CaseID        `json:"case"`
	Revision     int64         `json:"revision"`
	OK           bool          `json:"ok"`
	CheckedBlobs int           `json:"checked_blobs"`
	Issues       []VerifyIssue `json:"issues,omitempty"`
}

type ByteSearchSpec struct {
	Selection    SelectionID
	Literal      []byte
	Regexp       string
	ContextBytes int
	Limit        int
}
type ByteSearchHit struct {
	Object  ObjectID `json:"object"`
	Offset  int64    `json:"offset"`
	Length  int      `json:"length"`
	Context []byte   `json:"context,omitempty"`
}
type TextSearchHit struct {
	Artifact ArtifactID `json:"artifact"`
	Property string     `json:"property"`
	Text     string     `json:"text"`
}

type ActivityInfo struct {
	ID          ActivityID    `json:"id"`
	Session     SessionID     `json:"session,omitempty"`
	Agent       AgentID       `json:"agent"`
	Type        ActivityType  `json:"type"`
	Label       string        `json:"label"`
	CaptureMode CaptureMode   `json:"capture_mode"`
	State       ActivityState `json:"state"`
	StartedAt   time.Time     `json:"started_at"`
	FinishedAt  *time.Time    `json:"finished_at,omitempty"`
	Outcome     *Outcome      `json:"outcome,omitempty"`
}
type ProvenanceEdge struct {
	Activity  ActivityID `json:"activity"`
	Entity    EntityRef  `json:"entity"`
	Direction string     `json:"direction"`
	Role      string     `json:"role"`
}
type ProvenanceGraph struct {
	Root       EntityRef        `json:"root"`
	Entities   []EntityRef      `json:"entities"`
	Activities []ActivityInfo   `json:"activities"`
	Edges      []ProvenanceEdge `json:"edges"`
}

type MarkdownSpec struct {
	Selection                SelectionID
	Writer                   io.Writer
	IncludeHashes            bool
	IncludeProvenanceSummary bool
}
type JSONLSpec struct {
	Selection SelectionID
	Writer    io.Writer
}
type BagItSpec struct {
	Selection   SelectionID
	Destination string
	Name        string
}
type Deliverable struct {
	ID              DeliverableID `json:"id"`
	Selection       SelectionID   `json:"selection"`
	Path            string        `json:"path"`
	SHA256          string        `json:"sha256"`
	CreatedRevision int64         `json:"created_revision"`
}

func (d Deliverable) EntityRef() EntityRef {
	return EntityRef{ID: string(d.ID), Kind: EntityDeliverable}
}

type BagItReport struct {
	OK           bool          `json:"ok"`
	PayloadFiles int           `json:"payload_files"`
	Issues       []VerifyIssue `json:"issues,omitempty"`
}

type SnapshotSpec struct {
	Destination string `json:"destination"`
	Name        string `json:"name,omitempty"`
}
type RestoreSpec struct {
	Source string `json:"source"`
}
type PortableBlob struct {
	Blob BlobRef `json:"blob"`
	Size int64   `json:"size"`
	Path string  `json:"path"`
}
type PortableCaseManifest struct {
	Format        int            `json:"format"`
	Case          CaseID         `json:"case"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Revision      int64          `json:"revision"`
	AuditHead     string         `json:"audit_head"`
	CatalogSHA256 string         `json:"catalog_sha256"`
	Blobs         []PortableBlob `json:"blobs"`
}
type CheckpointSpec struct {
	Signer crypto.Signer `json:"-"`
	Writer io.Writer     `json:"-"`
}
type CheckpointInventory struct {
	Format        int            `json:"format"`
	Case          CaseID         `json:"case"`
	Revision      int64          `json:"revision"`
	AuditHead     string         `json:"audit_head"`
	CatalogSHA256 string         `json:"catalog_sha256"`
	Blobs         []PortableBlob `json:"blobs"`
}
type CheckpointSignature struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}
type Checkpoint struct {
	Inventory CheckpointInventory  `json:"inventory"`
	Signature *CheckpointSignature `json:"signature,omitempty"`
}

type ParserDescriptor struct {
	ID             string   `json:"id"`
	Version        string   `json:"version"`
	BuildDigest    string   `json:"build_digest,omitempty"`
	MediaTypes     []string `json:"media_types,omitempty"`
	SchemaVersions []string `json:"schema_versions,omitempty"`
	Deterministic  bool     `json:"deterministic"`
}
type ProbeResult struct {
	Supported  bool
	Confidence float64
	MediaType  string
}
type ParseRequest struct {
	Input    ObjectRef
	Reader   io.ReaderAt
	Size     int64
	Config   map[string]any
	Activity *Activity
}
type Parser interface {
	Descriptor() ParserDescriptor
	Probe(context.Context, ObjectReader) (ProbeResult, error)
	Parse(context.Context, ParseRequest, Sink) error
}
type ObjectReader interface {
	io.ReaderAt
	Size() int64
	Object() ObjectRef
}
type Sink interface {
	EmitArtifact(context.Context, ProducerKey, ArtifactDraft) (ArtifactRef, error)
	EmitObject(context.Context, ProducerKey, ObjectSpec, io.Reader) (ObjectRef, error)
	Relate(context.Context, ProducerKey, AssertionSpec) (AssertionRef, error)
	Flush(context.Context) error
}
