package main

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/rego"
)

// Test-only structs to avoid conflict with real plugin/api

type testPodSandbox struct {
	ID          string
	Name        string
	UID         string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
}

type testContainer struct {
	ID           string
	PodSandboxID string
	Name         string
	Labels       map[string]string
	Annotations  map[string]string
	Args         []string
	Env          []string
	Mounts       []map[string]interface{}
}

type testPlugin struct{}

// Test-only CreateContainer method
func (p *testPlugin) CreateContainer(ctx context.Context, pod *testPodSandbox, container *testContainer) (bool, error) {
	input := map[string]interface{}{
		"args":   container.Args,
		"env":    container.Env,
		"mounts": container.Mounts,
	}
	query := rego.New(
		rego.Query("data.nri.allow"),
		rego.Load([]string{"policy.rego"}, nil),
		rego.Input(input),
	)
	rs, err := query.Eval(ctx)
	if err != nil {
		return false, err
	}
	if len(rs) == 0 {
		return false, nil
	}
	allowed := rs[0].Expressions[0].Value.(bool)
	return allowed, nil
}

func TestCreateContainer_OPA(t *testing.T) {
	p := &testPlugin{}
	ctx := context.Background()

	pod := &testPodSandbox{
		ID:        "pod1",
		Name:      "test-pod",
		UID:       "uid1",
		Namespace: "default",
		Labels:    map[string]string{"app": "demo"},
	}

	container := &testContainer{
		ID:           "ctr1",
		PodSandboxID: "pod1",
		Name:         "test-container",
		Labels:       map[string]string{"role": "test"},
		Args:         []string{"run", "something"},
		Env:          []string{"FOO=bar"},
	}

	// Test with allowed args/env/mounts
	t.Log("Testing allowed case (no forbidden args, env, or mounts)")
	allowed, err := p.CreateContainer(ctx, pod, container)
	if err != nil {
		t.Fatalf("OPA evaluation failed: %v", err)
	}
	if !allowed {
		t.Errorf("Expected container to be allowed, got denied")
	}

	// Test with forbidden arg
	t.Log("Testing forbidden arg case")
	container.Args = []string{"forbidden-arg"}
	allowed, err = p.CreateContainer(ctx, pod, container)
	if err != nil {
		t.Fatalf("OPA evaluation failed: %v", err)
	}
	if allowed {
		t.Errorf("Expected container to be denied, got allowed")
	}

	// Test with forbidden env
	t.Log("Testing forbidden env case")
	container.Args = []string{"run"}
	container.Env = []string{"FORBIDDEN=1"}
	allowed, err = p.CreateContainer(ctx, pod, container)
	if err != nil {
		t.Fatalf("OPA evaluation failed: %v", err)
	}
	if allowed {
		t.Errorf("Expected container to be denied due to env, got allowed")
	}

	// Test with forbidden mount
	t.Log("Testing forbidden mount case")
	container.Env = []string{"FOO=bar"}
	container.Mounts = []map[string]interface{}{{"destination": "/forbidden"}}
	allowed, err = p.CreateContainer(ctx, pod, container)
	if err != nil {
		t.Fatalf("OPA evaluation failed: %v", err)
	}
	if allowed {
		t.Errorf("Expected container to be denied due to mount, got allowed")
	}
}
