package forensic

import "errors"

var (
	ErrNotFound           = errors.New("forensic: not found")
	ErrConflict           = errors.New("forensic: conflict")
	ErrBusy               = errors.New("forensic: busy")
	ErrIntegrity          = errors.New("forensic: integrity failure")
	ErrInvalid            = errors.New("forensic: invalid input")
	ErrUnsupported        = errors.New("forensic: unsupported")
	ErrUnsupportedStorage = errors.New("forensic: unsupported storage")
	ErrClosed             = errors.New("forensic: closed")
)

var (
	ErrInvalidInput     = ErrInvalid
	ErrIntegrityFailure = ErrIntegrity
)
