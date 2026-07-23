package forensic

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointAndPortableSnapshotRestore(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "evidence.bin", EvidenceSpec{Label: "portable", Acquisition: AcquisitionSpec{Method: "test"}}, bytes.NewReader([]byte("portable evidence")))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var checkpointJSON bytes.Buffer
	checkpoint, err := c.CreateCheckpoint(ctx, CheckpointSpec{Signer: privateKey, Writer: &checkpointJSON})
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Inventory.Case != c.ID() || len(checkpoint.Inventory.Blobs) != 1 {
		t.Fatalf("checkpoint inventory: %#v", checkpoint)
	}
	if err = VerifyCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	var decoded Checkpoint
	if err = json.Unmarshal(checkpointJSON.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if err = VerifyCheckpoint(decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Inventory.Revision++
	if err = VerifyCheckpoint(decoded); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered checkpoint = %v", err)
	}
	if _, err = c.CreateCheckpoint(ctx, CheckpointSpec{}); err != nil {
		t.Fatal(err)
	}
	if report, err := c.Verify(ctx, VerifySpec{Mode: VerifyQuick}); err != nil || !report.OK {
		t.Fatalf("stored checkpoint verification: %#v %v", report, err)
	}

	snapshotPath := filepath.Join(base, "portable-case")
	deliverable, err := c.Snapshot(ctx, SnapshotSpec{Destination: snapshotPath, Name: "portable case"})
	if err != nil {
		t.Fatal(err)
	}
	if deliverable.SHA256 == "" {
		t.Fatal("snapshot has no package digest")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(snapshotPath, "portable-case.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest PortableCaseManifest
	if err = json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Case != c.ID() || len(manifest.Blobs) != 1 {
		t.Fatalf("portable manifest: %#v", manifest)
	}
	restoredRepo, err := Open(ctx, Config{Root: filepath.Join(base, "restored-repository"), DefaultAgent: AgentSpec{Kind: AgentSoftware, Name: "test-agent"}})
	if err != nil {
		t.Fatal(err)
	}
	defer restoredRepo.Close()
	restored, err := restoredRepo.RestoreCase(ctx, RestoreSpec{Source: snapshotPath})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.ID() != c.ID() {
		t.Fatalf("restored case ID=%s want %s", restored.ID(), c.ID())
	}
	restoredObject, err := restored.Object(ctx, evidence.RootObject.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restoredObject.Blob != evidence.RootObject.Blob {
		t.Fatalf("restored blob=%s want %s", restoredObject.Blob, evidence.RootObject.Blob)
	}
	report, err := restored.Verify(ctx, VerifySpec{Mode: VerifyFull})
	if err != nil || !report.OK {
		t.Fatalf("restored verification: %#v %v", report, err)
	}

	corruptPath := filepath.Join(snapshotPath, filepath.FromSlash(manifest.Blobs[0].Path))
	if err = os.WriteFile(corruptPath, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	thirdRepo, err := Open(context.Background(), Config{Root: filepath.Join(base, "third-repository")})
	if err != nil {
		t.Fatal(err)
	}
	defer thirdRepo.Close()
	if _, err = thirdRepo.RestoreCase(ctx, RestoreSpec{Source: snapshotPath}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corrupt restore = %v", err)
	}
}
