//go:build !linux

package main

import "os"

// Non-Linux production mount generation fails closed before this input is
// consumed. Keep the file-shape check portable for command/unit builds.
func protectedClientSecretFileMetadata(info os.FileInfo) bool { return true }
