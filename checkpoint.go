package forensic

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

func (c *Case) CreateCheckpoint(ctx context.Context, spec CheckpointSpec) (Checkpoint, error) {
	if err := c.checkOpen(); err != nil {
		return Checkpoint{}, err
	}
	id, err := newID("checkpoint_")
	if err != nil {
		return Checkpoint{}, err
	}
	snapshot := filepath.Join(c.root, "staging", "package", id+".sqlite3")
	defer os.Remove(snapshot)
	if err = onlineBackup(ctx, c.db, snapshot); err != nil {
		return Checkpoint{}, err
	}
	db, err := openSQLite(ctx, snapshot, c.repo.busy)
	if err != nil {
		return Checkpoint{}, err
	}
	var cp Checkpoint
	cp.Inventory.Format = 1
	if err = db.QueryRowContext(ctx, "SELECT id,revision,audit_head FROM case_info WHERE singleton=1").Scan(&cp.Inventory.Case, &cp.Inventory.Revision, &cp.Inventory.AuditHead); err != nil {
		db.Close()
		return cp, err
	}
	rows, err := db.QueryContext(ctx, "SELECT DISTINCT b.digest,b.size FROM blobs b JOIN objects o ON o.blob_digest=b.digest ORDER BY b.digest")
	if err != nil {
		db.Close()
		return cp, err
	}
	for rows.Next() {
		var b PortableBlob
		if err = rows.Scan(&b.Blob, &b.Size); err != nil {
			rows.Close()
			db.Close()
			return cp, err
		}
		b.Path = portableBlobPath(b.Blob)
		cp.Inventory.Blobs = append(cp.Inventory.Blobs, b)
	}
	if err = rows.Close(); err != nil {
		db.Close()
		return cp, err
	}
	if err = db.Close(); err != nil {
		return cp, err
	}
	digest, _, err := digestFile(ctx, snapshot)
	if err != nil {
		return cp, err
	}
	cp.Inventory.CatalogSHA256 = digest
	body, err := canonicalJSON(cp.Inventory)
	if err != nil {
		return cp, err
	}
	if spec.Signer != nil {
		signature, err := signCheckpoint(spec.Signer, body)
		if err != nil {
			return cp, err
		}
		cp.Signature = signature
	}
	encoded, err := canonicalJSON(cp)
	if err != nil {
		return cp, err
	}
	encoded = append(encoded, '\n')
	if spec.Writer != nil {
		if _, err = spec.Writer.Write(encoded); err != nil {
			return cp, err
		}
	} else {
		path := filepath.Join(c.root, "checkpoints", fmt.Sprintf("%020d.json", cp.Inventory.Revision))
		if err = writeBytesAtomic(path, encoded); err != nil {
			return cp, err
		}
	}
	return cp, nil
}

func signCheckpoint(signer crypto.Signer, body []byte) (*CheckpointSignature, error) {
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	var sig []byte
	algorithm := "sha256"
	switch signer.Public().(type) {
	case ed25519.PublicKey:
		algorithm = "ed25519"
		sig, err = signer.Sign(rand.Reader, body, crypto.Hash(0))
	default:
		digest := sha256.Sum256(body)
		sig, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		return nil, err
	}
	return &CheckpointSignature{Algorithm: algorithm, PublicKey: base64.StdEncoding.EncodeToString(pub), Value: base64.StdEncoding.EncodeToString(sig)}, nil
}

func VerifyCheckpoint(cp Checkpoint) error {
	if cp.Signature == nil {
		return nil
	}
	body, err := canonicalJSON(cp.Inventory)
	if err != nil {
		return err
	}
	pubDER, err := base64.StdEncoding.DecodeString(cp.Signature.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: invalid checkpoint public key", ErrIntegrity)
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Signature.Value)
	if err != nil {
		return fmt.Errorf("%w: invalid checkpoint signature", ErrIntegrity)
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("%w: invalid checkpoint public key", ErrIntegrity)
	}
	digest := sha256.Sum256(body)
	valid := false
	switch p := pub.(type) {
	case ed25519.PublicKey:
		valid = cp.Signature.Algorithm == "ed25519" && ed25519.Verify(p, body, sig)
	case *rsa.PublicKey:
		valid = cp.Signature.Algorithm == "sha256" && rsa.VerifyPKCS1v15(p, crypto.SHA256, digest[:], sig) == nil
	case *ecdsa.PublicKey:
		valid = cp.Signature.Algorithm == "sha256" && ecdsa.VerifyASN1(p, digest[:], sig)
	}
	if !valid {
		return fmt.Errorf("%w: checkpoint signature verification failed", ErrIntegrity)
	}
	return nil
}

func writeBytesAtomic(path string, b []byte) error {
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return syncDirectory(filepath.Dir(path))
}
