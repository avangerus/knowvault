package workspaceapi

import "strconv"

// Paths are authorized source content, not instructions. Quoting preserves
// their exact identity while preventing embedded newlines from forging rows.
func mcpSourcePathText(path string) string {
	if path == "" {
		return ""
	}
	return " source_path=" + strconv.Quote(path)
}
