package postgres_test

// Card E-3: two question-set runs with different KNOWVAULT_QUESTION_SET_INSTANCE
// values must never share, reuse or remove each other's H5 database. The first
// test pins the resource names deterministically, without Docker or a model;
// the second runs instances 5 and 6 on the real model at the same time and
// proves the two H5 databases coexist, that each run reads its own, and that
// neither instance leaves a container or volume behind.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// TestQuestionSetInstanceResourcesAreDistinct pins result 1 of card E-3: for
// every instance 1..9 the H5 database's container, host port and volume, and
// every container and port the set already used, are distinct from each other.
// It also pins result 2: the default instance keeps every name and port the set
// uses today, and every resource other than the H5 ones keeps its old scheme.
func TestQuestionSetInstanceResourcesAreDistinct(t *testing.T) {
	t.Setenv("KNOWVAULT_QUESTION_SET_INSTANCE", "")
	base := loadE1aSet(t)
	baseH5 := base.Environment.UnconfirmedDatabase
	if strings.TrimSpace(baseH5.Volume) == "" {
		t.Fatal("the H5 database names no volume; two instances would share the container's anonymous one")
	}

	claimed := map[string]int{}
	claim := func(instance int, kind, name string) {
		key := kind + ":" + name
		if owner, ok := claimed[key]; ok {
			t.Fatalf("%s %q is used by instance %d and instance %d", kind, name, owner, instance)
		}
		claimed[key] = instance
	}

	for instance := 1; instance <= 9; instance++ {
		suffix := strconv.Itoa(instance)
		t.Setenv("KNOWVAULT_QUESTION_SET_INSTANCE", suffix)
		set := loadE1aSet(t)
		h5 := set.Environment.UnconfirmedDatabase

		claim(instance, "container", set.Environment.ProductContainer)
		claim(instance, "container", set.Environment.SourceContainer)
		claim(instance, "container", h5.Container)
		claim(instance, "port", strconv.Itoa(set.Environment.ProductPort))
		claim(instance, "port", strconv.Itoa(set.Environment.SourcePort))
		claim(instance, "port", strconv.Itoa(h5.Port))
		claim(instance, "volume", h5.Volume)

		// Result 2: a resource the set already used keeps its own scheme and
		// nothing but the H5 resources changed.
		if set.Environment.ProductContainer != base.Environment.ProductContainer+"-"+suffix ||
			set.Environment.ProductPort != base.Environment.ProductPort+10*instance ||
			set.Environment.SourceContainer != base.Environment.SourceContainer+"-"+suffix ||
			set.Environment.SourcePort != base.Environment.SourcePort+10*instance {
			t.Fatalf("instance %d changed a resource the set already used: product %s/%d, source %s/%d",
				instance, set.Environment.ProductContainer, set.Environment.ProductPort,
				set.Environment.SourceContainer, set.Environment.SourcePort)
		}
		// The H5 resources follow the same per-instance scheme.
		if h5.Container != baseH5.Container+"-"+suffix || h5.Port != baseH5.Port+10*instance || h5.Volume != baseH5.Volume+"-"+suffix {
			t.Fatalf("instance %d H5 resources = %s/%d/%s, want %s/%d/%s",
				instance, h5.Container, h5.Port, h5.Volume,
				baseH5.Container+"-"+suffix, baseH5.Port+10*instance, baseH5.Volume+"-"+suffix)
		}
	}
}

// e1aSideBySideRun is one child question-set run the side-by-side test started.
type e1aSideBySideRun struct {
	instance int
	report   string
	cmd      *exec.Cmd
	output   bytes.Buffer
	err      error
}

// TestQuestionSetInstancesRunSideBySide is the real-model half of result 1 of
// card E-3. It starts two question-set runs with instances 5 and 6 at the same
// time, limited to H5, and proves that both H5 databases run at the same time on
// their own host ports (so neither run removed the other's while it ran), that
// both finish with H5 read from their own database, and that neither instance
// leaves a container or volume behind.
//
// Each run needs its own product database and its own
// KNOWVAULT_QUESTION_SET_INSTANCE value, both process-wide, so the test starts
// itself as two child go test processes. It is skipped, never silently passed,
// without the DeepSeek key, like the one command.
func TestQuestionSetInstancesRunSideBySide(t *testing.T) {
	keyFile := strings.TrimSpace(os.Getenv("KNOWVAULT_QUESTION_SET_API_KEY_FILE"))
	if keyFile == "" {
		t.Skip("set KNOWVAULT_QUESTION_SET_API_KEY_FILE to the DeepSeek key file to run the real question set")
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("DeepSeek key file: %v", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker CLI is required for the side-by-side instances: %v", err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("the Go toolchain is required to start the two runs: %v", err)
	}
	root := repositoryRoot(t)

	instances := []int{5, 6}
	sets := map[int]*questions.Set{}
	containers := map[int][]string{}
	for _, instance := range instances {
		set, err := questions.LoadSet(filepath.Join(root, "tests", "e2e", "questions", "questions.json"))
		if err != nil {
			t.Fatalf("load question set: %v", err)
		}
		set.ApplyInstance(instance)
		sets[instance] = set
		containers[instance] = []string{
			set.Environment.ProductContainer,
			set.Environment.SourceContainer,
			set.Environment.UnconfirmedDatabase.Container,
		}
	}
	first, second := sets[5].Environment.UnconfirmedDatabase, sets[6].Environment.UnconfirmedDatabase
	if first.Container == second.Container || first.Port == second.Port || first.Volume == second.Volume {
		t.Fatalf("instances 5 and 6 share an H5 resource: %s/%d/%s and %s/%d/%s",
			first.Container, first.Port, first.Volume, second.Container, second.Port, second.Volume)
	}

	reportRoot := t.TempDir()
	runs := make([]*e1aSideBySideRun, 0, len(instances))
	var finished atomic.Int64
	var wg sync.WaitGroup
	for _, instance := range instances {
		dir := filepath.Join(reportRoot, fmt.Sprintf("instance-%d", instance))
		command := exec.Command("go", "test", "./tests/integration/postgres",
			"-run", "^TestQuestionSetRealModel$", "-count=1", "-v", "-timeout", "90m")
		command.Dir = root
		command.Env = append(os.Environ(),
			fmt.Sprintf("KNOWVAULT_QUESTION_SET_INSTANCE=%d", instance),
			"KNOWVAULT_QUESTION_SET_ONLY=H5",
			"KNOWVAULT_QUESTION_SET_API_KEY_FILE="+keyFile,
			"KNOWVAULT_QUESTION_SET_REPORT_DIR="+dir,
		)
		run := &e1aSideBySideRun{instance: instance, report: filepath.Join(dir, "report.json"), cmd: command}
		command.Stdout = &run.output
		command.Stderr = &run.output
		if err := command.Start(); err != nil {
			t.Fatalf("start question-set instance %d: %v", instance, err)
		}
		runs = append(runs, run)
		wg.Add(1)
		go func(run *e1aSideBySideRun) {
			defer wg.Done()
			run.err = run.cmd.Wait()
			finished.Add(1)
		}(run)
	}
	t.Cleanup(func() {
		for _, run := range runs {
			if run.cmd.Process != nil {
				_ = run.cmd.Process.Kill()
			}
		}
		wg.Wait()
		for _, instance := range instances {
			for _, name := range containers[instance] {
				e1aDockerQuiet("rm", "-f", "-v", name)
			}
			e1aDockerQuiet("volume", "rm", "-f", sets[instance].Environment.UnconfirmedDatabase.Volume)
		}
	})

	// The two H5 databases must be up at the same time: that is what proves
	// neither run removed the other's resource while it ran.
	coexisting := false
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		if e1aContainerRunning(first.Container) && e1aContainerRunning(second.Container) {
			coexisting = true
			break
		}
		if finished.Load() == int64(len(runs)) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	wg.Wait()
	if !coexisting {
		t.Fatalf("the H5 databases of instances 5 and 6 never ran at the same time\n--- instance 5 ---\n%s\n--- instance 6 ---\n%s",
			runs[0].output.String(), runs[1].output.String())
	}

	// Each run must have asked H5 against its own database: the report is the
	// product's own read of that database's source status, taken immediately
	// before the question. The H5 answer's own hard rules belong to card E-2
	// and a real-model answer may fail them; this test proves that the run
	// reached H5 and read its own database, so a red H5 answer is reported
	// here, never silently treated as an isolation result.
	for _, run := range runs {
		raw, err := os.ReadFile(run.report)
		if err != nil {
			t.Fatalf("instance %d wrote no report, so it never reached H5: %v\n%s", run.instance, err, run.output.String())
		}
		var report questions.Report
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatalf("instance %d report: %v", run.instance, err)
		}
		h5Runs := 0
		for _, item := range report.Runs {
			if item.QuestionID != "H5" {
				continue
			}
			h5Runs++
			if strings.TrimSpace(item.DatabaseName) == "" || !item.DatabaseAwaitingConfirmation {
				t.Fatalf("instance %d H5 run %d did not read its own database awaiting confirmation: %+v",
					run.instance, item.Run, item)
			}
		}
		if h5Runs != 3 {
			t.Fatalf("instance %d asked H5 %d times, want 3\n%s", run.instance, h5Runs, run.output.String())
		}
		if run.err != nil || report.Failed {
			t.Logf("instance %d H5 answer rules were red (err=%v report failed=%t); this test proves resource isolation, not the answer:\n%s",
				run.instance, run.err, report.Failed, run.output.String())
		}
	}

	// After both runs nothing of either instance may remain.
	for _, instance := range instances {
		for _, name := range containers[instance] {
			if e1aContainerExists(name) {
				t.Fatalf("instance %d left container %s behind", instance, name)
			}
		}
		if volume := sets[instance].Environment.UnconfirmedDatabase.Volume; e1aVolumeExists(volume) {
			t.Fatalf("instance %d left volume %s behind", instance, volume)
		}
	}
}

// e1aDockerNames runs one read-only docker listing and returns its lines.
func e1aDockerNames(args ...string) []string {
	output, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil
	}
	names := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// e1aContainerRunning reports whether a running container has exactly this name.
func e1aContainerRunning(name string) bool {
	for _, found := range e1aDockerNames("ps", "--filter", "name=^"+name+"$", "--format", "{{.Names}}") {
		if found == name {
			return true
		}
	}
	return false
}

// e1aContainerExists reports whether any container, running or not, has exactly
// this name.
func e1aContainerExists(name string) bool {
	for _, found := range e1aDockerNames("ps", "-a", "--filter", "name=^"+name+"$", "--format", "{{.Names}}") {
		if found == name {
			return true
		}
	}
	return false
}

// e1aVolumeExists reports whether a volume has exactly this name.
func e1aVolumeExists(name string) bool {
	for _, found := range e1aDockerNames("volume", "ls", "--filter", "name=^"+name+"$", "--format", "{{.Name}}") {
		if found == name {
			return true
		}
	}
	return false
}
