package standalone

import (
	"context"
	"encoding/json"
	"fmt"
	api "github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/agent/config"
	"github.com/kubev2v/migration-planner/internal/agent/fileio"
	"github.com/kubev2v/migration-planner/internal/agent/service"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	credentialsFileName      = config.CredentialsFile
	inventoryFileName        = config.InventoryFile
	inventoryHTMLFileName    = "inventory.html"
	defaultDataDir           = filepath.Join(GetEnv("HOME", "~"), "Downloads")
	defaultCredentialsDir    = "."
	defaultCollectionTimeout = 5 * time.Minute
)

type CollectOptions struct {
	opaPoliciesFolderPath string
	dataDir               string
	credentialsDir        string
	credentialsFilePath   string
	inventoryFilePath     string
	inventoryHTMLFilePath string
	username              string
	url                   string
	password              string
	collectionTimeout     time.Duration
	htmlReport            bool
}

func NewCollectOptions() *CollectOptions {
	return &CollectOptions{
		opaPoliciesFolderPath: GetEnv("OPA_POLICY_FOLDER_PATH", "/usr/share/opa/policies"),
	}
}

func NewCmdCollect() *cobra.Command {
	o := NewCollectOptions()
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Gather vCenter inventory",
		Example: "planner collect" +
			"--data-dir ~/Downloads " +
			"--credentials-dir /tmp",
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(cmd.Context(), args)
		},
		SilenceUsage: true,
	}
	o.Bind(cmd.Flags())
	return cmd
}

func (o *CollectOptions) Bind(fs *pflag.FlagSet) {
	fs.BoolVar(&o.htmlReport, "html", false, "")
	fs.StringVar(&o.dataDir, "data-dir", defaultDataDir, "directory where the agent will write its data")
	fs.StringVar(&o.credentialsDir, "credentials-dir", defaultCredentialsDir, "directory where credentials are stored")
	fs.StringVarP(&o.username, "username", "u", "", "vsphere username")
	fs.StringVarP(&o.password, "password", "p", "", "vsphere password")
	fs.StringVar(&o.url, "url", "", "vsphere url")
	fs.DurationVar(&o.collectionTimeout, "timeout", defaultCollectionTimeout, "collection timeout")
}

func (o *CollectOptions) Run(ctx context.Context, args []string) error {

	o.init()

	if err := o.validateCredential(); err != nil {
		return err
	}

	opaCmd, err := backgroundStartOPA(o.opaPoliciesFolderPath)
	if err != nil {
		return fmt.Errorf("error running opa server: %v", err)
	}
	defer opaCmd.Process.Kill()

	if err := o.collect(ctx, o.collectionTimeout); err != nil {
		err = fmt.Errorf("error generate the ivnentory.json: %v", err)
	}

	if o.htmlReport {
		if err := o.convertToHTML(); err != nil {
			return err
		}
	}

	return nil
}

func (o *CollectOptions) init() {

	o.inventoryFilePath = filepath.Join(o.dataDir, inventoryFileName)
	o.inventoryHTMLFilePath = filepath.Join(o.dataDir, inventoryHTMLFileName)
	o.credentialsFilePath = filepath.Join(o.credentialsDir, credentialsFileName)

}

func (o *CollectOptions) collect(ctx context.Context, timeout time.Duration) error {

	if _, err := os.Stat(o.inventoryFilePath); err == nil {
		if err := os.Remove(o.inventoryFilePath); err != nil {
			return err
		}
	}

	collector := service.NewCollector(o.dataDir, o.credentialsDir)
	collector.Collect(ctx)

	if err := waitForFile(o.inventoryFilePath, timeout); err != nil {
		return err
	}

	return nil
}

func (o *CollectOptions) saveCredential() error {
	if len(o.url) == 0 || len(o.username) == 0 || len(o.password) == 0 {
		return fmt.Errorf("error. Must pass url, username, and password")
	}

	credentials := &config.Credentials{
		URL:      o.url,
		Username: o.username,
		Password: o.password,
	}

	buf, _ := json.Marshal(credentials)
	writer := fileio.NewWriter()

	if err := writer.WriteFile(o.credentialsFilePath, buf); err != nil {
		return fmt.Errorf("failed saving credentials: %v", err)
	}

	return nil
}

func (o *CollectOptions) validateCredential() error {
	if o.username != "" {
		if err := o.saveCredential(); err != nil {
			return err
		}
	}

	if _, err := os.Stat(o.credentialsFilePath); err != nil {
		return fmt.Errorf("error reading credentials file: %v", err)
	}

	return nil
}

func backgroundStartOPA(policyDir string) (*exec.Cmd, error) {
	if _, err := os.Stat(policyDir); err != nil {
		return nil, fmt.Errorf("cannot find policies in %s: %w", policyDir, err)
	}

	if _, err := exec.LookPath("opa"); err != nil {
		return nil, fmt.Errorf("opa binary not found in PATH: %w", err)
	}

	cmd := exec.Command("opa", "run", policyDir, "--server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start opa: %w", err)
	}

	return cmd, nil
}

func GetEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func waitForFile(filename string, timeout time.Duration) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			return fmt.Errorf("timed out waiting for %s after %s", filename, timeout)

		case <-ticker.C:
			if _, err := os.Stat(filename); err == nil {
				return nil
			}
		}
	}
}

func (o *CollectOptions) convertToHTML() error {

	inv, err := o.loadInventory()
	if err != nil {
		return fmt.Errorf("error loading inventory: %v", err)
	}

	tmpl, err := template.ParseFiles("data/template.html")
	if err != nil {
		return fmt.Errorf("error to parse template: %v", err)
	}

	outputFile, err := os.Create(o.inventoryHTMLFilePath)
	if err != nil {
		return fmt.Errorf("error to create output HTML file: %v", err)
	}
	defer outputFile.Close()

	err = tmpl.Execute(outputFile, inv)
	if err != nil {
		return fmt.Errorf("error to execute template: %v", err)
	}

	return nil
}

func (o *CollectOptions) loadInventory() (*api.Inventory, error) {
	jsonBytes, err := os.ReadFile(o.inventoryFilePath)
	if err != nil {
		return nil, fmt.Errorf("error to read inventory file: %v", err)
	}

	var invData service.InventoryData
	if err := json.Unmarshal(jsonBytes, &invData); err != nil {
		return nil, fmt.Errorf("error to unmarshal JSON: %v", err)
	}

	return &invData.Inventory, nil
}
