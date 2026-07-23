package forensic

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
)

// ParseObject optionally probes and then runs one trusted in-process parser.
// Probe and parse receive independent readers. Outputs emitted before a parse
// error remain committed and the activity records a failed outcome.
func (s *Session) ParseObject(ctx context.Context, input ObjectRef, parser Parser, options ParseOptions) (ParseResult, error) {
	result := ParseResult{Input: input.ID}
	if err := s.checkOpen(); err != nil {
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	if parser == nil {
		err := fmt.Errorf("%w: parser is required", ErrInvalid)
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	descriptor := parser.Descriptor()
	result.Parser = descriptor
	if strings.TrimSpace(descriptor.ID) == "" || strings.TrimSpace(descriptor.Version) == "" {
		err := fmt.Errorf("%w: parser ID and version are required", ErrInvalid)
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	if options.MinimumConfidence < 0 || options.MinimumConfidence > 1 {
		err := fmt.Errorf("%w: parser confidence must be between zero and one", ErrInvalid)
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	config, err := cloneCanonicalConfig(options.Config)
	if err != nil {
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	if options.Probe {
		reader, openErr := s.caseRef.OpenObject(ctx, input.ID)
		if openErr != nil {
			result.Err, result.Error = openErr, openErr.Error()
			return result, openErr
		}
		probe, probeErr := parser.Probe(ctx, reader)
		closeReader(reader)
		result.Probe = &probe
		if probeErr != nil {
			result.Err, result.Error = probeErr, probeErr.Error()
			return result, probeErr
		}
		if probe.Confidence < 0 || probe.Confidence > 1 {
			err = fmt.Errorf("%w: parser returned invalid probe confidence", ErrInvalid)
			result.Err, result.Error = err, err.Error()
			return result, err
		}
		if !probe.Supported || probe.Confidence < options.MinimumConfidence {
			err = fmt.Errorf("%w: parser %s did not accept object %s", ErrUnsupported, descriptor.ID, input.ID)
			result.Err, result.Error = err, err.Error()
			return result, err
		}
	}
	cacheKey := ""
	if options.UseCache {
		if !descriptor.Deterministic {
			err = fmt.Errorf("%w: parser cache requires a deterministic parser descriptor", ErrInvalid)
			result.Err, result.Error = err, err.Error()
			return result, err
		}
		cacheKey, err = parserCacheKey(descriptor, config, input.ID)
		if err != nil {
			result.Err, result.Error = err, err.Error()
			return result, err
		}
		var source ActivityID
		var outputs []EntityRef
		source, outputs, err = s.caseRef.lookupParserCache(ctx, cacheKey)
		if err != nil && !errors.Is(err, ErrNotFound) {
			result.Err, result.Error = err, err.Error()
			return result, err
		}
		if err == nil {
			return s.recordParserReuse(ctx, input, descriptor, config, cacheKey, source, outputs, result.Probe)
		}
	}
	run, err := s.BeginActivity(ctx, ActivitySpec{
		Type: ActivityParse, Label: "Parse " + input.DisplayName,
		Tool:   &ToolDescriptor{Name: descriptor.ID, Version: descriptor.Version, BuildDigest: descriptor.BuildDigest},
		Config: config,
	})
	if err != nil {
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	result.Activity = run.ID()
	if err = run.Use(ctx, input, "source"); err != nil {
		_ = run.Finish(ctx, OutcomeFailed(err))
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	reader, err := s.caseRef.OpenObject(ctx, input.ID)
	if err != nil {
		_ = run.Finish(ctx, OutcomeFailed(err))
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	err = parser.Parse(ctx, ParseRequest{Input: input, Reader: reader, Size: input.Size, Config: config, Activity: run}, run)
	closeReader(reader)
	if err != nil {
		_ = run.Finish(ctx, OutcomeFailed(err))
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	if err = run.Finish(ctx, OutcomeSucceeded()); err != nil {
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	result.Outputs, err = s.caseRef.activityOutputEntities(ctx, run.ID())
	if err != nil {
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	if options.UseCache {
		if err = s.caseRef.storeParserCache(ctx, s, cacheKey, descriptor, config, input.ID, run.ID(), result.Outputs); err != nil {
			result.Err, result.Error = err, err.Error()
			return result, err
		}
	}
	return result, nil
}

// ParseMany uses one parser instance per input, so parser implementations need
// not be thread-safe. Result order always matches input order.
func (s *Session) ParseMany(ctx context.Context, factory ParserFactory, spec ParseManySpec) ([]ParseResult, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if factory == nil {
		return nil, fmt.Errorf("%w: parser factory is required", ErrInvalid)
	}
	if spec.Concurrency <= 0 {
		spec.Concurrency = min(max(1, runtime.GOMAXPROCS(0)), max(1, len(spec.Inputs)))
	}
	if spec.Concurrency > 64 {
		return nil, fmt.Errorf("%w: parser concurrency is too large", ErrInvalid)
	}
	if spec.MinimumConfidence < 0 || spec.MinimumConfidence > 1 {
		return nil, fmt.Errorf("%w: parser confidence must be between zero and one", ErrInvalid)
	}
	configJSON, err := canonicalJSON(spec.Config)
	if err != nil {
		return nil, err
	}
	results := make([]ParseResult, len(spec.Inputs))
	jobs := make(chan int)
	var workers sync.WaitGroup
	workerCount := min(spec.Concurrency, len(spec.Inputs))
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					results[index] = ParseResult{Input: spec.Inputs[index].ID, Err: ctx.Err(), Error: ctx.Err().Error()}
					continue
				}
				parser := factory.New()
				if parser == nil {
					err := fmt.Errorf("%w: parser factory returned nil", ErrInvalid)
					results[index] = ParseResult{Input: spec.Inputs[index].ID, Err: err, Error: err.Error()}
					continue
				}
				var config map[string]any
				if decodeErr := decodeCanonicalConfig(configJSON, &config); decodeErr != nil {
					results[index] = ParseResult{Input: spec.Inputs[index].ID, Err: decodeErr, Error: decodeErr.Error()}
					continue
				}
				results[index], _ = s.ParseObject(ctx, spec.Inputs[index], parser, ParseOptions{Config: config, Probe: spec.Probe, MinimumConfidence: spec.MinimumConfidence, UseCache: spec.UseCache})
			}
		}()
	}
	for index := range spec.Inputs {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			for i := index; i < len(results); i++ {
				if results[i].Input == "" {
					results[i] = ParseResult{Input: spec.Inputs[i].ID, Err: ctx.Err(), Error: ctx.Err().Error()}
				}
			}
			return results, ctx.Err()
		}
	}
	close(jobs)
	workers.Wait()
	return results, nil
}

func parserCacheKey(descriptor ParserDescriptor, config map[string]any, input ObjectID) (string, error) {
	digest, _, err := digestJSON(struct {
		Domain string
		Parser ParserDescriptor
		Config map[string]any
		Input  ObjectID
	}{"forensic-parser-cache-v1", descriptor, config, input})
	return digest, err
}

func (c *Case) lookupParserCache(ctx context.Context, key string) (ActivityID, []EntityRef, error) {
	var source ActivityID
	if err := c.db.QueryRowContext(ctx, "SELECT source_activity_id FROM parser_cache WHERE cache_key=?", key).Scan(&source); errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	} else if err != nil {
		return "", nil, mapSQLError(err)
	}
	rows, err := c.db.QueryContext(ctx, "SELECT e.id,e.kind FROM parser_cache_outputs p JOIN entities e ON e.id=p.entity_id WHERE p.cache_key=? ORDER BY p.ordinal", key)
	if err != nil {
		return "", nil, mapSQLError(err)
	}
	defer rows.Close()
	var outputs []EntityRef
	for rows.Next() {
		var output EntityRef
		if err = rows.Scan(&output.ID, &output.Kind); err != nil {
			return "", nil, err
		}
		outputs = append(outputs, output)
	}
	return source, outputs, rows.Err()
}

func (s *Session) recordParserReuse(ctx context.Context, input ObjectRef, descriptor ParserDescriptor, config map[string]any, cacheKey string, source ActivityID, outputs []EntityRef, probe *ProbeResult) (ParseResult, error) {
	result := ParseResult{Input: input.ID, Parser: descriptor, Probe: probe, Outputs: append([]EntityRef(nil), outputs...), Reused: true, ReusedFrom: source}
	activity, err := s.BeginActivity(ctx, ActivitySpec{
		Type: ActivityParserReuse, Label: "Reuse parse of " + input.DisplayName,
		Tool:   &ToolDescriptor{Name: descriptor.ID, Version: descriptor.Version, BuildDigest: descriptor.BuildDigest},
		Config: map[string]any{"parser_config": config, "cache_key": cacheKey, "source_activity": source}, CaptureMode: CaptureLibrary,
	})
	if err != nil {
		result.Err, result.Error = err, err.Error()
		return result, err
	}
	result.Activity = activity.ID()
	if err = activity.Use(ctx, input, "source"); err == nil {
		for _, output := range outputs {
			if err = activity.Use(ctx, output, "cached-output"); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = activity.Finish(ctx, Outcome{State: ActivitySucceeded, Summary: "reused immutable outputs from " + string(source)})
	} else {
		_ = activity.Finish(ctx, OutcomeFailed(err))
	}
	if err != nil {
		result.Err, result.Error = err, err.Error()
	}
	return result, err
}

func (c *Case) activityOutputEntities(ctx context.Context, activity ActivityID) ([]EntityRef, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT e.id,e.kind FROM activity_outputs o JOIN entities e ON e.id=o.entity_id WHERE o.activity_id=? ORDER BY o.role,e.id", activity)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var outputs []EntityRef
	for rows.Next() {
		var output EntityRef
		if err = rows.Scan(&output.ID, &output.Kind); err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
	}
	return outputs, rows.Err()
}

func (c *Case) storeParserCache(ctx context.Context, session *Session, key string, descriptor ParserDescriptor, config map[string]any, input ObjectID, source ActivityID, outputs []EntityRef) error {
	configDigest, _, err := digestJSON(config)
	if err != nil {
		return err
	}
	_, err = c.mutate(ctx, session.info.Agent.ID, session.ID(), "parser.cache", key, []string{key, string(source)}, func(tx *sql.Tx, revision int64) error {
		result, execErr := tx.ExecContext(ctx, "INSERT OR IGNORE INTO parser_cache(cache_key,parser_id,parser_version,parser_build_digest,config_digest,input_object_id,source_activity_id,created_revision) VALUES(?,?,?,?,?,?,?,?)", key, descriptor.ID, descriptor.Version, descriptor.BuildDigest, configDigest, input, source, revision)
		if execErr != nil {
			return execErr
		}
		inserted, _ := result.RowsAffected()
		if inserted == 0 {
			return errIdempotentReplay
		}
		for ordinal, output := range outputs {
			if _, execErr = tx.ExecContext(ctx, "INSERT INTO parser_cache_outputs(cache_key,ordinal,entity_id) VALUES(?,?,?)", key, ordinal, output.ID); execErr != nil {
				return execErr
			}
		}
		return nil
	})
	return err
}

func cloneCanonicalConfig(config map[string]any) (map[string]any, error) {
	body, err := canonicalJSON(config)
	if err != nil {
		return nil, err
	}
	var clone map[string]any
	if err = decodeCanonicalConfig(body, &clone); err != nil {
		return nil, err
	}
	return clone, nil
}

func decodeCanonicalConfig(body []byte, target *map[string]any) error {
	if bytes.Equal(body, []byte("null")) {
		*target = nil
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	return decoder.Decode(target)
}
