package e2e

import (
	"fmt"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"time"
)

var TestOptions = struct {
	DisconnectedEnvironment bool
}{}

const (
	DefaultOrganization = "admin"
	DefaultUsername     = "admin"
	DefaultEmailDomain  = "example.com"
	VmName              = "coreos-vm"
	Vsphere1Port        = "8989"
	Vsphere2Port        = "8990"
	AgentPort           = 3333
)

var (
	DefaultAgentTestID = "1"
	DefaultBasePath    = "/tmp/untarova/"
	DefaultVmdkName    = filepath.Join(DefaultBasePath, "persistence-disk.vmdk")
	DefaultOvaPath     = filepath.Join(Home, "myimage.ova")
	DefaultServiceUrl  = fmt.Sprintf("http://%s:7443/api/migration-assessment", SystemIP)
	Home               = os.Getenv("HOME")
	PrivateKeyPath     = filepath.Join(os.Getenv("E2E_PRIVATE_KEY_FOLDER_PATH"), "private-key")
	SystemIP           = os.Getenv("PLANNER_IP")
	TestsExecutionTime = make(map[string]time.Duration)
)

// Using agent as containers
var (
	AgentImagePath             = fmt.Sprintf("%s:5000/agent:latest", SystemIP)
	AgentDestDataDir           = "/app/.migration-planner/data"
	AgentDestPersistentDataDir = "/app/.migration-planner/persistent-data"
	AgentDestConfigDir         = "/app/.migration-planner/config"
	MountBasePath              = fmt.Sprintf("/tmp/agent-e2e-%s", uuid.New())
)
