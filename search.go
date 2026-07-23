package forensic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

func (c *Case) SearchText(ctx context.Context, literal string, limit int) ([]TextSearchHit, error) {
	if strings.TrimSpace(literal) == "" {
		return nil, fmt.Errorf("%w: search text is required", ErrInvalid)
	}
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		return nil, fmt.Errorf("%w: search limit is too large", ErrInvalid)
	}
	term := `"` + strings.ReplaceAll(literal, `"`, `""`) + `"`
	rows, err := c.db.QueryContext(ctx, "SELECT artifact_id,property,text FROM artifact_fts WHERE artifact_fts MATCH ? ORDER BY artifact_id,property,text LIMIT ?", term, limit)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var hits []TextSearchHit
	for rows.Next() {
		var h TextSearchHit
		if err = rows.Scan(&h.Artifact, &h.Property, &h.Text); err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

const byteSearchChunk = 64 << 10
const byteSearchRegexpWindow = 1 << 20

func (c *Case) SearchBytes(ctx context.Context, spec ByteSearchSpec) ([]ByteSearchHit, error) {
	if len(spec.Literal) == 0 && spec.Regexp == "" {
		return nil, fmt.Errorf("%w: literal or regexp is required", ErrInvalid)
	}
	if len(spec.Literal) > byteSearchRegexpWindow {
		return nil, fmt.Errorf("%w: literal is too large", ErrInvalid)
	}
	if spec.ContextBytes < 0 || spec.ContextBytes > 4096 {
		return nil, fmt.Errorf("%w: invalid context size", ErrInvalid)
	}
	if spec.Limit <= 0 {
		spec.Limit = 1000
	}
	var re *regexp.Regexp
	var err error
	if spec.Regexp != "" {
		re, err = regexp.Compile(spec.Regexp)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	selection, err := c.Selection(ctx, spec.Selection)
	if err != nil {
		return nil, err
	}
	var hits []ByteSearchHit
	for _, entity := range selection.Members {
		if entity.Kind != EntityObject && entity.Kind != EntityManifest {
			continue
		}
		obj, err := c.objectByEntity(ctx, entity.ID)
		if err != nil {
			return nil, err
		}
		reader, err := c.OpenObject(ctx, obj.ID)
		if err != nil {
			return nil, err
		}
		for base := int64(0); base < obj.Size && len(hits) < spec.Limit; base += byteSearchChunk {
			if err = ctx.Err(); err != nil {
				closeReader(reader)
				return nil, err
			}
			before := int64(spec.ContextBytes)
			if before > base {
				before = base
			}
			lookahead := len(spec.Literal) - 1
			if re != nil {
				lookahead = byteSearchRegexpWindow
			}
			readStart := base - before
			readEnd := base + byteSearchChunk + int64(lookahead+spec.ContextBytes)
			if readEnd > obj.Size {
				readEnd = obj.Size
			}
			buf := make([]byte, int(readEnd-readStart))
			n, readErr := reader.ReadAt(buf, readStart)
			buf = buf[:n]
			if readErr != nil && readErr != io.EOF {
				closeReader(reader)
				return nil, readErr
			}
			var matches [][]int
			if re != nil {
				matches = re.FindAllIndex(buf, spec.Limit-len(hits))
			} else {
				for off := 0; len(matches) < spec.Limit-len(hits); {
					i := bytes.Index(buf[off:], spec.Literal)
					if i < 0 {
						break
					}
					start := off + i
					matches = append(matches, []int{start, start + len(spec.Literal)})
					off = start + max(1, len(spec.Literal))
				}
			}
			for _, m := range matches {
				absolute := readStart + int64(m[0])
				if absolute < base || absolute >= base+byteSearchChunk {
					continue
				}
				lo := max(0, m[0]-spec.ContextBytes)
				hi := min(len(buf), m[1]+spec.ContextBytes)
				hits = append(hits, ByteSearchHit{Object: obj.ID, Offset: absolute, Length: m[1] - m[0], Context: append([]byte(nil), buf[lo:hi]...)})
				if len(hits) >= spec.Limit {
					break
				}
			}
		}
		closeReader(reader)
		if len(hits) >= spec.Limit {
			break
		}
	}
	return hits, nil
}

func closeReader(r ObjectReader) {
	if c, ok := r.(io.Closer); ok {
		_ = c.Close()
	}
}
