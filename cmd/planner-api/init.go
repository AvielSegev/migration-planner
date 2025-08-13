package main

import (
	"context"
	"fmt"
	"github.com/kubev2v/migration-planner/internal/api_server/isoserver"
	"github.com/kubev2v/migration-planner/pkg/log"
	"github.com/spf13/pflag"
	"go.uber.org/zap/zapcore"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubev2v/migration-planner/internal/config"
	"github.com/kubev2v/migration-planner/internal/util"
	"github.com/kubev2v/migration-planner/pkg/iso"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type InitOptions struct {
	Serve bool
	Port  string
}

func DefaultInitOptions() *InitOptions {
	return &InitOptions{
		Serve: false,
	}
}

func NewCmdInit() *cobra.Command {
	o := DefaultInitOptions()
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize RHCOS ISO for the migration planner",
		RunE: func(cmd *cobra.Command, args []string) error {

			defer zap.S().Info("ISO initialization completed")

			cfg, err := config.New()
			if err != nil {
				zap.S().Fatalw("reading configuration", "error", err)
			}

			logLvl, err := zap.ParseAtomicLevel(cfg.Service.LogLevel)
			if err != nil {
				logLvl = zap.NewAtomicLevelAt(zapcore.InfoLevel)
			}

			logger := log.InitLog(logLvl)
			defer func() { _ = logger.Sync() }()

			undo := zap.ReplaceGlobals(logger)
			defer undo()

			zap.S().Info("Starting ISO initialization...")

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
			defer cancel()

			// Initialize ISOs
			zap.S().Info("Initializing RHCOS ISO")
			isoInitializer := newIsoInitializer(cfg)
			targetIsoFile := util.GetEnv("MIGRATION_PLANNER_ISO_PATH", "rhcos-live-iso.x86_64.iso")
			if err := isoInitializer.Initialize(ctx, targetIsoFile, cfg.Service.RhcosImageSha256); err != nil {
				zap.S().Fatalw("failed to initialize iso", "error", err)
			}
			zap.S().Info("RHCOS ISO initialized successfully")

			if o.Serve {
				addr := fmt.Sprintf("0.0.0.0:%s", o.Port)
				listener, err := newListener(addr)
				if err != nil {
					zap.S().Named("iso_server").Fatalw("creating listener", "error", err)
				}
				isoServer := isoserver.New(listener, addr, targetIsoFile)
				if err := isoServer.Run(ctx); err != nil {
					zap.S().Named("iso_server").Fatalw("failed to run iso server", "error", err)
				}
			}

			return nil
		},
	}
	o.Bind(cmd.Flags())
	return cmd
}

func (o *InitOptions) Bind(fs *pflag.FlagSet) {
	fs.BoolVar(&o.Serve, "listen", false, "listen to serve the iso file")
	fs.StringVarP(&o.Port, "port", "p", "8080", "Port to listen on")
}

func newIsoInitializer(cfg *config.Config) *iso.IsoInitializer {
	md := iso.NewDownloaderManager()

	minio, err := iso.NewMinioDownloader(
		iso.WithEndpoint(cfg.Service.S3.Endpoint),
		iso.WithBucket(cfg.Service.S3.Bucket),
		iso.WithAccessKey(cfg.Service.S3.AccessKey),
		iso.WithSecretKey(cfg.Service.S3.SecretKey),
		iso.WithImage(cfg.Service.S3.IsoFileName, cfg.Service.RhcosImageSha256),
	)
	if err == nil {
		md.Register(minio)
	} else {
		zap.S().Errorw("failed to create minio downloader", "error", err)
	}

	// register the default downloader of the official RHCOS image.
	md.Register(iso.NewHttpDownloader(cfg.Service.RhcosImageName, cfg.Service.RhcosImageSha256))

	return iso.NewIsoInitializer(md)
}
