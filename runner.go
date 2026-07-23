package forensic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	defaultRunLogLimit    = int64(8 << 20)
	defaultRunOutputFiles = 10_000
	defaultRunOutputBytes = int64(16 << 30)
)

// RunExperiment owns a local process execution and records what it could
// directly observe. It is an execution/capture boundary, not a sandbox.
func (s *Session) RunExperiment(ctx context.Context, spec RunSpec) (result RunResult, err error) {
	if err = s.checkOpen(); err != nil {
		return result, err
	}
	if spec.Projection == "" || strings.TrimSpace(spec.Command) == "" {
		return result, fmt.Errorf("%w: projection and command are required", ErrInvalid)
	}
	if spec.MaxLogBytes <= 0 {
		spec.MaxLogBytes = defaultRunLogLimit
	}
	if spec.MaxOutputFiles <= 0 {
		spec.MaxOutputFiles = defaultRunOutputFiles
	}
	if spec.MaxOutputBytes <= 0 {
		spec.MaxOutputBytes = defaultRunOutputBytes
	}
	if spec.MaxLogBytes > 1<<30 || spec.MaxOutputFiles > 1_000_000 || spec.MaxOutputBytes > 1<<50 {
		return result, fmt.Errorf("%w: runner resource limit is too large", ErrInvalid)
	}
	outputs, err := normalizeRunOutputs(spec.OutputPaths, spec.MaxOutputFiles)
	if err != nil {
		return result, err
	}
	if err = validateRunEnvironment(spec.InheritEnvironment, spec.Environment); err != nil {
		return result, err
	}
	materialization, err := s.Materialize(ctx, spec.Projection, DirectoryTarget{Writable: true})
	if err != nil {
		return result, err
	}
	result.Materialization = materialization
	if err = protectProjectionInputs(materialization.Destination); err != nil {
		return result, err
	}
	workingDirectory, err := runWorkingDirectory(materialization.Destination, spec.WorkingDirectory)
	if err != nil {
		return result, err
	}
	if spec.Label == "" {
		spec.Label = "Run " + filepath.Base(spec.Command)
	}
	execution := &ExecutionDescriptor{
		Command:          spec.Command,
		Arguments:        append([]string(nil), spec.Arguments...),
		WorkingDirectory: filepath.ToSlash(spec.WorkingDirectory),
		Environment:      cloneStringMap(spec.Environment),
		Sandbox:          spec.Sandbox,
	}
	activity, err := s.BeginActivity(ctx, ActivitySpec{Type: ActivityExperiment, Label: spec.Label, Tool: spec.Tool, Config: spec.Config, CaptureMode: CaptureWrapped, Execution: execution})
	if err != nil {
		return result, err
	}
	result.Activity = activity.ID()
	finished := false
	defer func() {
		if !finished {
			_ = activity.Finish(context.WithoutCancel(ctx), OutcomeFailed(err))
		}
	}()
	projection, err := s.caseRef.Projection(ctx, spec.Projection)
	if err != nil {
		return result, err
	}
	if err = activity.Use(ctx, projection, "projection"); err != nil {
		return result, err
	}
	if err = activity.Use(ctx, materialization.Manifest, "projection-manifest"); err != nil {
		return result, err
	}
	if err = activity.SealInputs(ctx); err != nil {
		return result, err
	}

	command := exec.CommandContext(ctx, spec.Command, spec.Arguments...)
	command.Dir = workingDirectory
	command.Env = buildRunEnvironment(spec.InheritEnvironment, spec.Environment)
	stdout, stderr := &boundedBuffer{limit: spec.MaxLogBytes}, &boundedBuffer{limit: spec.MaxLogBytes}
	command.Stdout, command.Stderr = stdout, stderr
	runErr := command.Run()
	result.LogsTruncated = stdout.truncated || stderr.truncated
	result.Stdout, err = activity.Capture(ctxOrBackground(ctx), ObjectSpec{Role: "stdout", DisplayName: "stdout.log", MediaType: "text/plain"}, bytes.NewReader(stdout.Bytes()))
	if err != nil {
		return result, err
	}
	result.Stderr, err = activity.Capture(ctxOrBackground(ctx), ObjectSpec{Role: "stderr", DisplayName: "stderr.log", MediaType: "text/plain"}, bytes.NewReader(stderr.Bytes()))
	if err != nil {
		return result, err
	}
	var total int64
	for _, relative := range outputs {
		full, size, openErr := regularOutputPath(materialization.Destination, relative)
		if openErr != nil {
			err = openErr
			return result, err
		}
		total += size
		if total > spec.MaxOutputBytes {
			return result, fmt.Errorf("%w: runner output size limit exceeded", ErrInvalid)
		}
		captured, captureErr := activity.CaptureFile(ctxOrBackground(ctx), full, ObjectSpec{Role: "experiment-output", DisplayName: filepath.Base(relative), Source: PathLocator{Display: "output/" + filepath.ToSlash(relative), Separator: "/"}})
		if captureErr != nil {
			return result, captureErr
		}
		result.Outputs = append(result.Outputs, captured)
	}
	result.InputCheck, err = s.caseRef.Verify(ctxOrBackground(ctx), VerifySpec{Mode: VerifyProjection, Materialization: materialization.ID})
	if err != nil {
		return result, err
	}
	outcome := OutcomeSucceeded()
	if runErr != nil {
		outcome = OutcomeFailed(runErr)
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			code := exitErr.ExitCode()
			outcome.ExitCode = &code
		}
	}
	if ctx.Err() != nil {
		outcome = OutcomeCancelled()
	}
	if !result.InputCheck.OK {
		outcome.State = ActivityFailed
		outcome.Warnings = append(outcome.Warnings, "projected input changed during wrapped execution")
	}
	if result.LogsTruncated {
		outcome.Warnings = append(outcome.Warnings, "stdout or stderr was truncated at the configured limit")
	}
	if err = activity.Finish(ctxOrBackground(ctx), outcome); err != nil {
		return result, err
	}
	finished = true
	result.Outcome = outcome
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

func normalizeRunOutputs(paths []string, limit int) ([]string, error) {
	if len(paths) > limit {
		return nil, fmt.Errorf("%w: runner output file limit exceeded", ErrInvalid)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.ToSlash(strings.TrimSpace(path))
		if !safeRelativePath(path) || path == "." {
			return nil, fmt.Errorf("%w: unsafe runner output path %q", ErrInvalid, path)
		}
		key := strings.ToLower(path)
		if seen[key] {
			return nil, fmt.Errorf("%w: duplicate runner output path %q", ErrInvalid, path)
		}
		seen[key] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func safeRelativePath(path string) bool {
	if path == "" || strings.ContainsRune(path, '\x00') || filepath.IsAbs(filepath.FromSlash(path)) || filepath.VolumeName(filepath.FromSlash(path)) != "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return clean == path && path != ".." && !strings.HasPrefix(path, "../")
}

func runWorkingDirectory(workspace, relative string) (string, error) {
	if relative == "" || relative == "." {
		return workspace, nil
	}
	relative = filepath.ToSlash(relative)
	if !safeRelativePath(relative) {
		return "", fmt.Errorf("%w: unsafe working directory", ErrInvalid)
	}
	full := filepath.Join(workspace, filepath.FromSlash(relative))
	if ok, _ := pathWithin(workspace, full); !ok {
		return "", fmt.Errorf("%w: working directory escapes workspace", ErrInvalid)
	}
	info, err := os.Stat(full)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: working directory is not a directory", ErrInvalid)
	}
	return full, nil
}

func protectProjectionInputs(workspace string) error {
	body, err := os.ReadFile(filepath.Join(workspace, "projection-manifest.json"))
	if err != nil {
		return err
	}
	var manifest ProjectionManifest
	if err = json.Unmarshal(body, &manifest); err != nil {
		return err
	}
	for _, entry := range manifest.Entries {
		if err = os.Chmod(filepath.Join(workspace, filepath.FromSlash(entry.Path)), 0400); err != nil {
			return err
		}
	}
	for _, file := range manifest.Files {
		if err = os.Chmod(filepath.Join(workspace, filepath.FromSlash(file.Path)), 0400); err != nil {
			return err
		}
	}
	return os.Chmod(filepath.Join(workspace, "projection-manifest.json"), 0400)
}

func regularOutputPath(workspace, relative string) (string, int64, error) {
	root := filepath.Join(workspace, "output")
	full := filepath.Join(root, filepath.FromSlash(relative))
	if ok, _ := pathWithin(root, full); !ok {
		return "", 0, fmt.Errorf("%w: output escapes workspace", ErrInvalid)
	}
	current := root
	parts := strings.Split(filepath.FromSlash(relative), string(os.PathSeparator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", 0, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", 0, fmt.Errorf("%w: output path contains a symlink", ErrInvalid)
		}
	}
	info, err := os.Lstat(full)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: declared output is not a regular file", ErrInvalid)
	}
	return full, info.Size(), nil
}

func buildRunEnvironment(inherit []string, values map[string]string) []string {
	environment := map[string]string{}
	for _, key := range inherit {
		if value, ok := os.LookupEnv(key); ok {
			environment[key] = value
		}
	}
	for key, value := range values {
		environment[key] = value
	}
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+environment[key])
	}
	return out
}

func validateRunEnvironment(inherit []string, values map[string]string) error {
	for _, key := range inherit {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return fmt.Errorf("%w: invalid inherited environment name", ErrInvalid)
		}
	}
	for key, value := range values {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%w: invalid process environment", ErrInvalid)
		}
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx.Err() != nil {
		return context.WithoutCancel(ctx)
	}
	return ctx
}

type boundedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = b.truncated || original > 0
		return original, nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(data)
	return original, nil
}

func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }
