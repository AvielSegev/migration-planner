package cli

import (
	"context"
	"fmt"
	"github.com/kubev2v/migration-planner/internal/agent/service"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type CollectOptions struct {
	PoliciesFolderPath string
	dataDir            string
	credentialsDir     string
}

func NewCollectOptions() *CollectOptions {
	return &CollectOptions{
		PoliciesFolderPath: GetEnv("OPA_POLICY_FOLDER_PATH", "/usr/share/opa/policies"),
		dataDir:            "/home/asegev/work/test-agent/data",
		credentialsDir:     "/home/asegev/work/test-agent/persistent-data-dir",
	}
}

func NewCmdCollect() *cobra.Command {
	o := NewCollectOptions()
	cmd := &cobra.Command{
		Use:     "collect",
		Short:   "",
		Example: "",
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(cmd.Context(), args)
		},
		SilenceUsage: true,
	}
	o.Bind(cmd.Flags())
	return cmd
}

func (o *CollectOptions) Bind(fs *pflag.FlagSet) {

}

func (o *CollectOptions) Run(ctx context.Context, args []string) error {

	opaCmd, err := backgroundStartOPA(o.PoliciesFolderPath)
	if err != nil {
		return fmt.Errorf("error running opa server: %v", err)
	}
	defer opaCmd.Process.Kill()

	collector := service.NewCollector(o.dataDir, o.credentialsDir)
	collector.Collect(ctx) // Todo: Figure why c.Run is working but Collect(ctx) dont
	
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

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("OPA exited unexpectedly: %v", err)
		}
	}()

	return cmd, nil
}

func GetEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}
