package store

import (
	"github.com/kubev2v/migration-planner/internal/config"
	"github.com/kubev2v/migration-planner/internal/store"
)

func NewStore() (store.Store, error) {
	cfg, err := config.New()
	if err != nil {
		return nil, err
	}

	db, err := store.InitDB(cfg)
	if err != nil {
		return nil, err
	}

	return store.NewStore(db), nil
}
