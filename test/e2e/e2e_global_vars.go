package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var TestOptions = struct {
	DisconnectedEnvironment bool
}{}

const (
	DefaultOrganization          string = "admin"
	DefaultUsername              string = "admin"
	DefaultKeyCloakAdminUsername string = "admin"
	DefaultKeyCloakAdminPassword string = "admin"
	DefaultKeyCloakRealm         string = "planner"
	VmName                       string = "coreos-vm"
	Vsphere1Port                 string = "8989"
	Vsphere2Port                 string = "8990"
)

var (
	DefaultAgentTestID string = "1"
	DefaultBasePath    string = "/tmp/untarova/"
	DefaultVmdkName    string = filepath.Join(DefaultBasePath, "persistence-disk.vmdk")
	DefaultOvaPath     string = filepath.Join(Home, "myimage.ova")
	DefaultServiceUrl  string = fmt.Sprintf("http://%s:7443/api/migration-assessment", SystemIP)
	DefaultKeyCloakUrl string = fmt.Sprintf("http://%s:8080", SystemIP)
	Home               string = os.Getenv("HOME")
	PrivateKeyPath     string = filepath.Join(os.Getenv("E2E_PRIVATE_KEY_FOLDER_PATH"), "private-key")
	SystemIP           string = os.Getenv("PLANNER_IP")
	TestsExecutionTime        = make(map[string]time.Duration)
)
