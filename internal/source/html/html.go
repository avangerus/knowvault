// Package html is the typed owner of safe folder-HTML extraction for the P2/I2
// format matrix. It turns a connected `.html`/`.htm` file into deterministic,
// normalized visible text so the file becomes exactly-anchored TEXT line-range
// Evidence (PARSER_CONTRACTS.md §1 "HTML file → TEXT line range", §5).
//
// Retrieved HTML is untrusted data, so the extractor is deliberately narrow and
// fail-closed:
//
//   - it only parses the byte tree with the pinned golang.org/x/net/html tree
//     builder — it never executes script, never evaluates CSS, and never opens a
//     network or filesystem resource, so active content and remote/external
//     references (scripts, styles, forms, event handlers, frames, meta-refresh,
//     images, links) are inert and their URLs never enter the canonical text;
//   - active, embedded and metadata subtrees (script/style/head/template/iframe/
//     object/embed/svg/math/form/controls/dialog/…) — including browser-fallback
//     content that is invisible when the UA is capable (noscript/noframes/noembed)
//     — and elements carrying the boolean `hidden` attribute are dropped whole
//     before any text is collected, so they contribute no Evidence
//     (PARSER_CONTRACTS.md §5);
//   - only the visible inline text of the remaining block structure is emitted,
//     one logical line per block, ASCII-whitespace-collapsed to a single form and
//     canonicalized to text-v1, so a re-extraction of the exact source bytes with
//     the same parser profile reproduces the identical canonical bytes, hashes and
//     TEXT anchors;
//   - input size, node count, nesting depth and output size are all bounded. The
//     input-size cap (with the connector's per-scope MaxFileBytes) bounds the tree
//     the builder materializes before the walk runs, and x/net/html caps its
//     open-element stack at 512 so a nesting bomb fails closed at parse time; the
//     node/depth/output caps bound the walk. A limit breach is a per-object
//     quarantine, and a document with no extractable visible text is a quarantine
//     with no fallback (PARSER_CONTRACTS.md §2);
//   - the parser returns only a sentinel error — no source markup or text ever
//     reaches a log, job, audit record or error.
//
// HTML has no DTD/entity mechanism, so there is no XXE or entity-expansion surface;
// the tree builder decodes only the fixed HTML named/numeric character references.
//
// Accepted hidden-content policy (locked by fixtures and the html-v1 profile hash):
// text hidden by the HTML `hidden` attribute or living in a dropped subtree
// (script/style/head/template/…) is never extracted; text hidden only by CSS
// (e.g. `style="display:none"`) IS extracted, because this profile evaluates no CSS.
// Preformatted (`<pre>`) whitespace is normalized like all other flow content;
// layout is not preserved in html-v1. `<br>` and block boundaries are the only
// line breaks.
package html

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// ErrQuarantine means the document is not safely extractable: it is not valid
// UTF-8, it breaches a structural bound (node/nesting/output limit), it cannot be
// parsed, or it yields no visible text. The caller quarantines the object with no
// Evidence and no fallback.
var ErrQuarantine = errors.New("html: document is not extractable")

// Limits bounds the parsed tree and the produced text so a nesting/node/size bomb
// cannot exhaust resources. A legitimate HTML document stays well within them.
type Limits struct {
	MaxInputBytes  int64
	MaxNodes       int
	MaxDepth       int
	MaxOutputBytes int
}

// DefaultLimits are the production bounds. The connector already caps the file at
// the scope's MaxFileBytes (the primary input bound); MaxInputBytes is the
// extractor's own independent cap and is deliberately small — a folder-HTML file
// is a document, not a multi-megabyte payload — so the tree the builder
// materializes before the walk runs is bounded (parse cost and allocation are
// O(input), and x/net/html itself caps the open-element stack at 512, failing a
// nesting bomb closed at parse time). MaxNodes/MaxDepth/MaxOutputBytes are the
// secondary caps applied during the walk.
var DefaultLimits = Limits{
	MaxInputBytes:  4 << 20,
	MaxNodes:       1 << 20,
	MaxDepth:       2048,
	MaxOutputBytes: 8 << 20,
}

// Extract parses raw HTML bytes and returns the text-v1 canonical UTF-8 visible
// text, one logical line per block, with the production limits. An empty result,
// an invalid-UTF-8 input, a parse failure or a limit breach quarantines.
func Extract(raw []byte) ([]byte, error) { return ExtractWithLimits(raw, DefaultLimits) }

// ExtractWithLimits is Extract with explicit limits (tests tighten each bound to
// prove it fails closed).
func ExtractWithLimits(raw []byte, limits Limits) ([]byte, error) {
	if int64(len(raw)) > limits.MaxInputBytes {
		return nil, ErrQuarantine
	}
	// The connector already gates whole-file UTF-8, but the extractor re-validates:
	// a mislabelled byte stream is never canonicalized into trusted Evidence.
	if !utf8.Valid(raw) {
		return nil, ErrQuarantine
	}
	root, err := xhtml.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrQuarantine
	}
	e := &extractor{limits: limits}
	if err := e.walk(root, 0); err != nil {
		return nil, err
	}
	e.flushLine()
	if len(e.lines) == 0 {
		return nil, ErrQuarantine
	}
	text := strings.Join(e.lines, "\n") + "\n"
	canonical, err := canon.Canonicalize([]byte(text))
	if err != nil {
		return nil, ErrQuarantine
	}
	if len(bytes.TrimSpace(canonical)) == 0 {
		return nil, ErrQuarantine
	}
	return canonical, nil
}

// extractor accumulates visible inline text into logical lines as it walks the
// tree depth-first.
type extractor struct {
	limits       Limits
	lines        []string
	cur          strings.Builder
	pendingSpace bool
	lineHasText  bool
	nodes        int
	outBytes     int
}

// walk processes one node. A dropped element's whole subtree is skipped before any
// of its text is collected; a block boundary flushes the current line; a `<br>`
// breaks a line; text nodes contribute collapsed visible text.
func (e *extractor) walk(n *xhtml.Node, depth int) error {
	e.nodes++
	if e.nodes > e.limits.MaxNodes || depth > e.limits.MaxDepth {
		return ErrQuarantine
	}
	switch n.Type {
	case xhtml.ElementNode:
		if isDropped(n.DataAtom, n.Data) || hasHiddenAttr(n) {
			return nil
		}
		if n.DataAtom == atom.Br {
			e.flushLine()
			return nil
		}
		block := isBlock(n.DataAtom)
		if block {
			e.flushLine()
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := e.walk(c, depth+1); err != nil {
				return err
			}
		}
		if block {
			e.flushLine()
		}
	case xhtml.TextNode:
		if err := e.appendText(n.Data); err != nil {
			return err
		}
	case xhtml.DocumentNode:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := e.walk(c, depth+1); err != nil {
				return err
			}
		}
	default:
		// Comment, doctype and other nodes contribute no visible text.
	}
	return nil
}

// appendText appends a text node's visible content to the current line, collapsing
// every run of ASCII whitespace to a single space and dropping leading/trailing
// space, so the same visible text always canonicalizes to the same bytes.
func (e *extractor) appendText(s string) error {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if isASCIISpace(r) {
			if e.lineHasText {
				e.pendingSpace = true
			}
			i += size
			continue
		}
		if e.pendingSpace {
			e.cur.WriteByte(' ')
			e.outBytes++
			e.pendingSpace = false
		}
		e.cur.WriteRune(r)
		e.outBytes += size
		e.lineHasText = true
		if e.outBytes > e.limits.MaxOutputBytes {
			return ErrQuarantine
		}
		i += size
	}
	return nil
}

// flushLine emits the current inline buffer as one logical line if it holds any
// visible text, then resets the buffer. An empty buffer produces no line, so block
// boundaries and consecutive `<br>` never create blank lines.
func (e *extractor) flushLine() {
	if e.lineHasText {
		e.lines = append(e.lines, e.cur.String())
	}
	e.cur.Reset()
	e.pendingSpace = false
	e.lineHasText = false
}

func isASCIISpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

// hasHiddenAttr reports whether the element carries the boolean HTML `hidden`
// attribute, whose subtree is dropped (accepted hidden-content policy).
func hasHiddenAttr(n *xhtml.Node) bool {
	for _, a := range n.Attr {
		if a.Namespace == "" && strings.EqualFold(a.Key, "hidden") {
			return true
		}
	}
	return false
}

// droppedAtoms is the closed set of active, embedded, scripting, metadata and
// form-control elements whose entire subtree contributes no visible Evidence text
// (PARSER_CONTRACTS.md §5). head carries title/meta/link/style/script.
var droppedAtoms = map[atom.Atom]bool{
	// Document metadata / head.
	atom.Head: true, atom.Base: true, atom.Basefont: true, atom.Link: true,
	atom.Meta: true, atom.Title: true, atom.Style: true,
	// Scripting and browser-fallback content that is invisible when the UA is
	// capable: noscript/noframes/noembed render ONLY when scripting/frames/embeds
	// are unavailable, so in a real browser they are never seen — extracting them
	// would let an attacker plant text (e.g. prompt-injection) no human reviewing
	// the page ever sees. They are dropped like active content.
	atom.Script: true, atom.Noscript: true, atom.Noframes: true, atom.Noembed: true,
	atom.Template: true,
	// Embedded / active / replaced content.
	atom.Iframe: true, atom.Frame: true, atom.Frameset: true, atom.Object: true,
	atom.Embed: true, atom.Applet: true, atom.Canvas: true, atom.Audio: true,
	atom.Video: true, atom.Source: true, atom.Track: true, atom.Param: true,
	atom.Map: true, atom.Area: true, atom.Svg: true, atom.Math: true, atom.Picture: true,
	// Forms and interactive controls.
	atom.Form: true, atom.Button: true, atom.Input: true, atom.Select: true,
	atom.Option: true, atom.Optgroup: true, atom.Datalist: true, atom.Output: true,
	atom.Textarea: true, atom.Progress: true, atom.Meter: true, atom.Fieldset: true,
	atom.Legend: true, atom.Label: true, atom.Menu: true,
	// A <dialog> is display:none by default (visible only when opened), another
	// invisible-by-default surface; it is dropped rather than extracted.
	atom.Dialog: true,
}

// droppedTags covers elements by name (defensive; the atom set covers the standard
// cases, but a duplicated by-name gate means a future edit that drops an atom entry
// still fails closed for these invisible/active elements).
var droppedTags = map[string]bool{
	"svg": true, "math": true, "script": true, "style": true,
	"noscript": true, "noframes": true, "noembed": true, "template": true,
	"iframe": true, "object": true, "embed": true, "form": true, "dialog": true,
}

func isDropped(a atom.Atom, data string) bool {
	if droppedAtoms[a] {
		return true
	}
	if a == 0 && droppedTags[strings.ToLower(data)] {
		return true
	}
	return false
}

// blockAtoms is the set of block-level elements whose boundaries flush the current
// line, so each block's visible text becomes its own logical line and a
// deterministic TEXT line range.
var blockAtoms = map[atom.Atom]bool{
	atom.Address: true, atom.Article: true, atom.Aside: true, atom.Blockquote: true,
	atom.Details: true, atom.Dd: true, atom.Div: true, atom.Dl: true,
	atom.Dt: true, atom.Figcaption: true, atom.Figure: true, atom.Footer: true,
	atom.H1: true, atom.H2: true, atom.H3: true, atom.H4: true, atom.H5: true, atom.H6: true,
	atom.Header: true, atom.Hgroup: true, atom.Hr: true, atom.Li: true, atom.Main: true,
	atom.Nav: true, atom.Ol: true, atom.P: true, atom.Pre: true, atom.Section: true,
	atom.Table: true, atom.Thead: true, atom.Tbody: true, atom.Tfoot: true, atom.Tr: true,
	atom.Td: true, atom.Th: true, atom.Ul: true, atom.Caption: true, atom.Colgroup: true,
	atom.Summary: true, atom.Body: true, atom.Html: true,
}

func isBlock(a atom.Atom) bool { return blockAtoms[a] }
