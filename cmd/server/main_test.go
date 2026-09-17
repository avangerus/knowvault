package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/composition"
)

func TestStartupErrorLogArgsAlwaysEmitSafeCodeAndStage(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "main.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	stageDerivations := 0
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "startupErrorLogArgs" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "StartupStageOf" {
				return true
			}
			packageName, packageOK := selector.X.(*ast.Ident)
			argument, argumentOK := call.Args[0].(*ast.Ident)
			if packageOK && argumentOK && packageName.Name == "composition" && argument.Name == "err" {
				stageDerivations++
			}
			return true
		})
	}
	if stageDerivations != 1 {
		t.Fatalf("startup log must derive exactly one allowlisted stage from composition.StartupStageOf(err), got %d", stageDerivations)
	}

	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)

	const secret = "database-password-should-not-appear"
	slog.Error("component startup rejected", startupErrorLogArgs(errors.New(secret))...)

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode startup log: %v; output=%q", err, output.String())
	}
	if got := record["error_code"]; got != string(composition.CodeConfigInvalid) {
		t.Fatalf("error_code = %v, want %q", got, composition.CodeConfigInvalid)
	}
	if got := record["startup_stage"]; got != string(composition.StartupStageUnknown) {
		t.Fatalf("startup_stage = %v, want %q", got, composition.StartupStageUnknown)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("startup log leaked underlying error: %q", output.String())
	}
}
