package main

import (
	"context"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/server"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"log"
	"os"
)

func main() {
	log.Printf("▶️  Launching OPA server from policies at %s", "")
	if err := backgroundStartOPA(context.Background(), ""); err != nil {
		panic(err)
	}
}

func backgroundStartOPA(ctx context.Context, policyDir string) error {
	configData, err := os.ReadFile("/home/asegev/work/migration-planner/opa-config.yaml")
	if err != nil {
		return err
	}

	store := inmem.New()

	mgr, err := plugins.New(configData, "bundles", store)
	if err != nil {
		log.Fatalf("failed to create plugin manager: %v", err)
	}

	if err := mgr.Init(ctx); err != nil {
		return err
	}

	if err := mgr.Start(ctx); err != nil {
		return err
	}
	
	opaSrv := server.New().
		WithAddresses([]string{
			"127.0.0.1:8181",
		}).
		WithStore(store).
		WithManager(mgr)

	// Initialize and kick off the HTTP listeners
	if _, err := opaSrv.Init(ctx); err != nil {
		log.Fatalf("server init error: %v", err)
	}
	listeners, err := opaSrv.Listeners()
	for _, loop := range listeners {
		go func(l server.Loop) {
			if err := l(); err != nil {
				log.Fatalf("server listen error: %v", err)
			}
		}(loop)
	}

	log.Println("OPA server started on 127.0.0.1:8181")
	select {} // block forever

	return nil
}
