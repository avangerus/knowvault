//go:build !windows

package postgres_test

import "syscall"

// makeFIFO creates a named pipe so the connector can prove a non-regular object
// is quarantined rather than read.
func makeFIFO(path string) error {
	return syscall.Mkfifo(path, 0o644)
}
