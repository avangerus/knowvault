package question

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

func TestResearchDeadlineLeavesFinalizationAndCitationTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		research, stopResearch := toolLoopResearchContext(ctx, time.Now())
		defer stopResearch()
		deadline, _ := research.Deadline()
		if got := time.Until(deadline); got != 120*time.Second {
			t.Fatalf("research budget = %s, want 120s", got)
		}
		// Advance only the fake clock. A blocking research model/tool call
		// exits at this deadline while completed observations remain usable.
		time.Sleep(120 * time.Second)
		synctest.Wait()
		if !toolLoopResearchExpired(ctx, research) || ctx.Err() != nil {
			t.Fatal("research expiry consumed the final-answer budget")
		}
		if !errors.Is(toolLoopOperationContext(ctx, research, false).Err(), context.DeadlineExceeded) {
			t.Fatal("another research operation received a fresh budget")
		}
		finalCtx := toolLoopOperationContext(ctx, research, true)
		calls := 0
		runtime := finalizationRuntime{catalog: func(received context.Context, _ workspacetools.Scope) ([]workspacetools.Definition, error) {
			calls++
			if received != ctx || received.Err() != nil {
				t.Fatal("finalization lost the original live request context")
			}
			return nil, nil
		}}
		definitions, err := toolFinalizationDefinitions(finalCtx, runtime, workspacetools.Scope{})
		if err != nil || calls != 1 || len(definitions) != 1 || definitions[0].Function.Name != submitAnswerToolName {
			t.Fatalf("cannot finalize after research expires: definitions=%v err=%v", definitions, err)
		}
		// A final answer can spend part of the reserve, leaving the original
		// context live for system citation verification, never a detached one.
		time.Sleep(40 * time.Second)
		citationCtx := toolLoopOperationContext(ctx, research, true)
		if citationCtx != ctx || citationCtx.Err() != nil {
			t.Fatal("citation verification cannot use the remaining reserve")
		}
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if !errors.Is(citationCtx.Err(), context.DeadlineExceeded) || toolLoopResearchExpired(ctx, research) {
			t.Fatal("finalization extended the overall request deadline")
		}
	})
}

func TestResearchReserveRespectsEarlierCallerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent, stopParent := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopParent()
		ctx, cancel := context.WithTimeout(parent, 180*time.Second)
		defer cancel()
		research, stopResearch := toolLoopResearchContext(ctx, time.Now())
		defer stopResearch()
		deadline, _ := research.Deadline()
		if got := time.Until(deadline); got != 20*time.Second {
			t.Fatalf("research budget = %s, want 20s within caller budget", got)
		}
	})
}

func TestResearchExpiryDoesNotOverrideClientCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent, stopParent := context.WithCancel(context.Background())
		defer stopParent()
		ctx, cancel := context.WithTimeout(parent, 180*time.Second)
		defer cancel()
		research, stopResearch := toolLoopResearchContext(ctx, time.Now())
		defer stopResearch()
		time.Sleep(120 * time.Second)
		synctest.Wait()
		stopParent()
		if toolLoopResearchExpired(ctx, research) {
			t.Fatal("client cancellation was mistaken for recoverable research expiry")
		}
		runtime := finalizationRuntime{catalog: func(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error) {
			t.Fatal("cancelled request entered finalization admission")
			return nil, nil
		}}
		_, err := toolFinalizationDefinitions(toolLoopOperationContext(ctx, research, true), runtime, workspacetools.Scope{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("finalization after client cancellation = %v", err)
		}
	})
}
