package forensic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type stagedBlob struct {
	ref    BlobRef
	digest string
	size   int64
	path   string
}

func (c *Case) stageBlob(ctx context.Context, r io.Reader) (stagedBlob, error) {
	if err := c.checkOpen(); err != nil {
		return stagedBlob{}, err
	}
	if r == nil {
		return stagedBlob{}, fmt.Errorf("%w: nil content reader", ErrInvalid)
	}
	id, err := newID("tmp_")
	if err != nil {
		return stagedBlob{}, err
	}
	path := filepath.Join(c.root, "staging", "ingest", id+".partial")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return stagedBlob{}, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err = c.injectFault("after-stage-create"); err != nil {
		return stagedBlob{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), &contextReader{ctx: ctx, r: r})
	if err != nil {
		return stagedBlob{}, err
	}
	if err = c.injectFault("after-stage-copy"); err != nil {
		return stagedBlob{}, err
	}
	if err = f.Sync(); err != nil {
		return stagedBlob{}, err
	}
	if err = c.injectFault("after-stage-sync"); err != nil {
		return stagedBlob{}, err
	}
	if err = f.Close(); err != nil {
		return stagedBlob{}, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	s := stagedBlob{ref: BlobRef("sha256:" + digest), digest: digest, size: n, path: path}
	ok = true
	return s, nil
}

func (c *Case) publishBlob(ctx context.Context, s stagedBlob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	final := c.blobPath(s.ref)
	if err := os.MkdirAll(filepath.Dir(final), 0700); err != nil {
		return err
	}
	err := os.Link(s.path, final)
	if err == nil {
		if injected := c.injectFault("after-blob-publish"); injected != nil {
			return injected
		}
		if err = os.Remove(s.path); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(final))
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: atomic no-replace publication is unavailable: %v", ErrUnsupportedStorage, err)
	}
	if err = verifyBlobFile(ctx, final, s.ref, s.size); err != nil {
		return fmt.Errorf("%w: published blob collision: %v", ErrIntegrity, err)
	}
	return os.Remove(s.path)
}

func (c *Case) blobPath(ref BlobRef) string {
	d := strings.TrimPrefix(string(ref), "sha256:")
	if len(d) < 4 {
		return filepath.Join(c.root, "blobs", "sha256", "invalid")
	}
	return filepath.Join(c.root, "blobs", "sha256", d[:2], d[2:4], d)
}

func verifyBlobFile(ctx context.Context, path string, ref BlobRef, size int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != size {
		return fmt.Errorf("size is %d, want %d", st.Size(), size)
	}
	h := sha256.New()
	if _, err = io.Copy(h, &contextReader{ctx: ctx, r: f}); err != nil {
		return err
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != string(ref) {
		return fmt.Errorf("digest is %s, want %s", got, ref)
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.r.Read(p)
	}
}

type managedObjectReader struct {
	*os.File
	object ObjectRef
}

func (r *managedObjectReader) Size() int64       { return r.object.Size }
func (r *managedObjectReader) Object() ObjectRef { return r.object }
