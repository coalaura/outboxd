package smtpd

import (
	"bufio"
	"errors"
	"io"
	"reflect"
	"unsafe"
)

// go-smtp v0.24.0 counts only emitted message bytes, then needs one further
// byte of budget to consume DATA's dot terminator. Keep the public server limit
// exact and extend only that private per-command reader. A dependency layout
// change fails closed rather than silently restoring the off-by-one behavior.
func allowDataTerminator(r io.Reader, maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}

	// go-smtp v0.24.0 uses this concrete reader only for BDAT, whose chunk
	// accounting enforces MaxMessageBytes before calling Session.Data.
	if _, ok := r.(*io.PipeReader); ok {
		return nil
	}

	typ := reflect.TypeOf(r)
	if typ == nil || typ.Kind() != reflect.Pointer || typ.Elem().PkgPath() != "github.com/emersion/go-smtp" || typ.Elem().Name() != "dataReader" {
		return errors.New("unsupported go-smtp DATA reader type")
	}

	elem := typ.Elem()

	wantFields := []struct {
		name string
		typ  reflect.Type
	}{
		{"r", reflect.TypeFor[*bufio.Reader]()},
		{"state", reflect.TypeFor[int]()},
		{"limited", reflect.TypeFor[bool]()},
		{"n", reflect.TypeFor[int64]()},
	}

	if elem.NumField() != len(wantFields) {
		return errors.New("unsupported go-smtp DATA reader layout")
	}

	for i, want := range wantFields {
		field := elem.Field(i)
		if field.Name != want.name || field.Type != want.typ {
			return errors.New("unsupported go-smtp DATA reader layout")
		}
	}

	reader := reflect.ValueOf(r).Elem()
	limited := reader.FieldByName("limited")
	value := reader.FieldByName("n")

	if !limited.Bool() || !value.CanAddr() || value.Int() != maxBytes {
		return errors.New("unsupported go-smtp DATA reader state")
	}

	reflect.NewAt(value.Type(), unsafe.Pointer(value.UnsafeAddr())).Elem().SetInt(incrementLimit(maxBytes))

	return nil
}
