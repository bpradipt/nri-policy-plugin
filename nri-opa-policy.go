package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type config struct {
	PolicyFile string   `json:"policyFile"`
	Events     []string `json:"events"`
	LogFile    string   `json:"logFile"`
}

type plugin struct {
	stub      stub.Stub
	mask      stub.EventMask
	policy    string
	policyRaw []byte
}

var (
	cfg config
	log *logrus.Logger
	_   = stub.ConfigureInterface(&plugin{})
)

func (p *plugin) Configure(_ context.Context, config, runtime, version string) (stub.EventMask, error) {
	log.Infof("got configuration data: %q from runtime %s %s", config, runtime, version)
	if config == "" {
		return p.mask, nil
	}

	oldCfg := cfg
	err := yaml.Unmarshal([]byte(config), &cfg)
	if err != nil {
		return 0, fmt.Errorf("failed to parse provided configuration: %w", err)
	}

	p.mask, err = api.ParseEventMask(cfg.Events...)
	if err != nil {
		return 0, fmt.Errorf("failed to parse events in configuration: %w", err)
	}

	if cfg.LogFile != oldCfg.LogFile && cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Errorf("failed to open log file %q: %v", cfg.LogFile, err)
			return 0, fmt.Errorf("failed to open log file %q: %w", cfg.LogFile, err)
		}
		log.SetOutput(f)
	}

	if cfg.PolicyFile != "" {
		policyRaw, err := os.ReadFile(cfg.PolicyFile)
		if err != nil {
			return 0, fmt.Errorf("failed to read OPA policy file: %w", err)
		}
		p.policy = string(policyRaw)
		p.policyRaw = policyRaw
	}

	return p.mask, nil
}

func (p *plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	input := map[string]interface{}{
		"args":   container.Args,
		"env":    container.Env,
		"mounts": container.Mounts,
	}
	ctx := context.Background()
	r := rego.New(
		rego.Query("data.nri.allow"),
		rego.Module("policy.rego", p.policy),
	)
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare OPA policy: %w", err)
	}
	inputJSON, _ := json.Marshal(input)
	var inputObj interface{}
	_ = json.Unmarshal(inputJSON, &inputObj)
	results, err := query.Eval(ctx, rego.EvalInput(inputObj))
	if err != nil {
		return nil, nil, fmt.Errorf("OPA policy evaluation error: %w", err)
	}
	allowed := false
	if len(results) > 0 && len(results[0].Expressions) > 0 {
		if b, ok := results[0].Expressions[0].Value.(bool); ok {
			allowed = b
		}
	}
	if !allowed {
		return nil, nil, fmt.Errorf("container creation denied by OPA policy")
	}
	return &api.ContainerAdjustment{}, nil, nil
}

// Implement other stub methods as no-ops or logging only
func (p *plugin) Synchronize(_ context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	return nil, nil
}
func (p *plugin) Shutdown()                                                     {}
func (p *plugin) RunPodSandbox(_ context.Context, pod *api.PodSandbox) error    { return nil }
func (p *plugin) StopPodSandbox(_ context.Context, pod *api.PodSandbox) error   { return nil }
func (p *plugin) RemovePodSandbox(_ context.Context, pod *api.PodSandbox) error { return nil }
func (p *plugin) PostCreateContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) error {
	return nil
}
func (p *plugin) StartContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) error {
	return nil
}
func (p *plugin) PostStartContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) error {
	return nil
}
func (p *plugin) UpdateContainer(_ context.Context, pod *api.PodSandbox, container *api.Container, r *api.LinuxResources) ([]*api.ContainerUpdate, error) {
	return nil, nil
}
func (p *plugin) PostUpdateContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) error {
	return nil
}
func (p *plugin) StopContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) ([]*api.ContainerUpdate, error) {
	return nil, nil
}
func (p *plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) error {
	return nil
}
func (p *plugin) onClose() { os.Exit(0) }

func main() {
	var (
		pluginName string
		pluginIdx  string
		events     string
		policyFile string
		logFile    string
		opts       []stub.Option
		err        error
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{PadLevelText: true})

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.StringVar(&events, "events", "CreateContainer", "comma-separated list of events to subscribe for (default: CreateContainer)")
	flag.StringVar(&policyFile, "policy-file", "policy.rego", "OPA policy file to load (default: policy.rego)")
	flag.StringVar(&logFile, "log-file", "", "logfile name, if logging to a file")
	flag.Parse()

	cfg.PolicyFile = policyFile
	cfg.LogFile = logFile
	if events != "" {
		cfg.Events = append(cfg.Events, events)
	}

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open log file %q: %v", cfg.LogFile, err)
		}
		log.SetOutput(f)
	}

	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}

	p := &plugin{}
	if p.mask, err = api.ParseEventMask(events); err != nil {
		log.Fatalf("failed to parse events: %v", err)
	}
	cfg.Events = append(cfg.Events, events)

	if p.stub, err = stub.New(p, append(opts, stub.WithOnClose(p.onClose))...); err != nil {
		log.Fatalf("failed to create plugin stub: %v", err)
	}

	if cfg.PolicyFile != "" {
		policyRaw, err := os.ReadFile(cfg.PolicyFile)
		if err != nil {
			log.Fatalf("failed to read OPA policy file: %w", err)
		}
		log.Infof("Successfully read policy file")
		p.policy = string(policyRaw)
		p.policyRaw = policyRaw
	}

	err = p.stub.Run(context.Background())
	if err != nil {
		log.Errorf("plugin exited with error %v", err)
		os.Exit(1)
	}
}
