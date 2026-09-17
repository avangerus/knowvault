//go:build windows

package postgres_test

import "errors"

// makeFIFO has no Windows equivalent; the non-regular case is skipped there and
// covered by the POSIX proof plus the Windows junction reparse case.
func makeFIFO(string) error {
	return errors.New("fifo unsupported on windows")
}
