package agent

import (
	"context"
	"fmt"
	"github.com/containers/podman/v6/pkg/bindings"
	"github.com/containers/podman/v6/pkg/bindings/containers"
	"github.com/containers/podman/v6/pkg/specgen"
	"github.com/coreos/ignition/v2/config/util"
	"github.com/google/uuid"
	"github.com/kubev2v/migration-planner/internal/agent/client"
	. "github.com/kubev2v/migration-planner/internal/util"
	"github.com/kubev2v/migration-planner/test/e2e"
	. "github.com/kubev2v/migration-planner/test/e2e/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"go.uber.org/zap"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sigs.k8s.io/yaml"

	agentConfig "github.com/kubev2v/migration-planner/internal/agent/config"
)

type plannerAgentPodman struct {
	conn                     context.Context
	imagePath                string
	containerID              string
	configDir                string
	DataDir                  string
	PersistentDataDir        string
	MountedDataDir           string
	MountedPersistentDataDir string
	MountedConfigDir         string
	sourceID                 uuid.UUID
	config                   agentConfig.Config
}

func NewPlannerAgentPodman(sourceID uuid.UUID, imagePath, dataDir, persistentDataDir, configDir string) (PlannerAgent, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	conn, err := bindings.NewConnection(context.Background(), fmt.Sprintf("unix:/run/user/%s/podman/podman.sock", u.Uid))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to podman socket: %w", err)
	}

	return &plannerAgentPodman{
		conn:                     conn,
		imagePath:                imagePath,
		DataDir:                  dataDir,
		PersistentDataDir:        persistentDataDir,
		configDir:                configDir,
		MountedDataDir:           path.Join(e2e.MountBasePath, "data"),
		MountedPersistentDataDir: path.Join(e2e.MountBasePath, "persistent-data"),
		MountedConfigDir:         path.Join(e2e.MountBasePath, "config"),
		sourceID:                 sourceID,
		config: agentConfig.Config{
			ConfigDir:         configDir,
			DataDir:           dataDir,
			PersistentDataDir: persistentDataDir,
			SourceID:          sourceID.String(),
			PlannerService: agentConfig.PlannerService{
				Config: client.Config{
					Service: client.Service{
						Server: e2e.DefaultServiceUrl,
					},
				},
			},
			UpdateInterval: Duration{Duration: agentConfig.DefaultUpdateInterval},
		},
	}, nil
}

func (p *plannerAgentPodman) Run() error {
	spec, err := p.spec()
	if err != nil {
		return err
	}

	if err := p.prepare(); err != nil {
		return err
	}

	createResponse, err := containers.CreateWithSpec(p.conn, spec, nil)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	p.containerID = createResponse.ID

	if err := containers.Start(p.conn, p.containerID, nil); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	zap.S().Infof("Container %s started successfully\n", p.containerID)

	return nil
}

func (p *plannerAgentPodman) prepare() error {
	// Ensure directories exist
	if err := os.MkdirAll(p.MountedPersistentDataDir, 0777); err != nil {
		return fmt.Errorf("failed to create persistent data dir: %v", err)
	}
	if err := os.MkdirAll(p.MountedDataDir, 0777); err != nil {
		return fmt.Errorf("failed to create data dir: %v", err)
	}
	if err := os.MkdirAll(p.MountedConfigDir, 0777); err != nil {
		return fmt.Errorf("failed to create config dir: %v", err)
	}

	// Write random UUID into the agent_id file
	if err := os.WriteFile(filepath.Join(p.MountedPersistentDataDir, "agent_id"), []byte(uuid.New().String()), 0644); err != nil {
		return fmt.Errorf("Failed to write agent_id: %v\n", err)
	}

	// Write JWT token
	jwt, err := GetAgentToken(context.Background(), p.sourceID)
	if err != nil {
		return fmt.Errorf("failed to create agent token: %v", err)
	}

	if err := os.WriteFile(filepath.Join(p.MountedDataDir, "jwt.json"), []byte(jwt), 0644); err != nil {
		return fmt.Errorf("Failed to write jwt.json: %v\n", err)
	}

	// Write config
	config, err := yaml.Marshal(p.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.MountedConfigDir, "config.yaml"), config, 0644); err != nil {
		return fmt.Errorf("Failed to write config.yaml: %v\n", err)
	}

	return nil
}

func (p *plannerAgentPodman) spec() (*specgen.SpecGenerator, error) {

	spec := specgen.NewSpecGenerator(p.imagePath, false)
	spec.Name = "planner-agent-e2e"

	spec.NetNS = specgen.Namespace{
		NSMode: specgen.Host,
	}

	spec.Mounts = []specs.Mount{
		{
			Source:      p.MountedDataDir,
			Destination: p.DataDir,
			Type:        "bind",
			Options:     []string{"Z"},
		},
		{
			Source:      p.MountedPersistentDataDir,
			Destination: p.PersistentDataDir,
			Type:        "bind",
			Options:     []string{"Z"},
		},
		{
			Source:      p.MountedConfigDir,
			Destination: p.configDir,
			Type:        "bind",
			Options:     []string{"Z"},
		},
	}

	spec.Command = []string{"-config", filepath.Join(p.configDir, "config.yaml")}
	spec.User = "0:0"

	return spec, nil
}

func (p *plannerAgentPodman) DumpLogs(_ string) {
	if p.containerID == "" {
		zap.S().Warn("No container ID found, cannot dump logs")
		return
	}

	stdoutChan := make(chan string)
	stderrChan := make(chan string)

	go func() {
		for msg := range stdoutChan {
			fmt.Print(msg)
		}
	}()
	go func() {
		for msg := range stderrChan {
			fmt.Print(msg)
		}
	}()

	err := containers.Logs(p.conn, p.containerID, &containers.LogOptions{
		Stdout:     util.BoolToPtr(true),
		Stderr:     util.BoolToPtr(true),
		Timestamps: util.BoolToPtr(true),
	}, stdoutChan, stderrChan)
	if err != nil {
		zap.S().Errorf("Failed to fetch logs for container %s: %v", p.containerID, err)
	}

	close(stdoutChan)
	close(stderrChan)
}

func (p *plannerAgentPodman) GetIp() (string, error) {
	return e2e.SystemIP, nil
}

func (p *plannerAgentPodman) IsServiceRunning(_ string, _ string) bool {
	return true
}

func (p *plannerAgentPodman) Restart() error {
	return nil
}

func (p *plannerAgentPodman) Remove() error {
	removeOptions := new(containers.RemoveOptions)
	removeOptions.Force = util.BoolToPtr(true)
	removeOptions.Volumes = util.BoolToPtr(true)

	if _, err := containers.Remove(p.conn, p.containerID, removeOptions); err != nil {
		return fmt.Errorf("failed to remove container %s: %w", p.containerID, err)
	}

	zap.S().Infof("Container %s removed successfully", p.containerID)

	if err := os.RemoveAll(e2e.MountBasePath); err != nil {
		return fmt.Errorf("error removing files :%w", err)
	}

	zap.S().Infof("mounted files and dirs removed.")

	return nil
}
