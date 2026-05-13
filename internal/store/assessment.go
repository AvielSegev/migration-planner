package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	api "github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/internal/util"
	"github.com/kubev2v/migration-planner/pkg/metrics"
	"go.uber.org/zap"
)

type Assessment interface {
	List(ctx context.Context, filter *AssessmentQueryFilter) (model.AssessmentList, error)
	Get(ctx context.Context, id uuid.UUID) (*model.Assessment, error)
	Create(ctx context.Context, assessment model.Assessment, inventory []byte) (*model.Assessment, error)
	Update(ctx context.Context, assessmentID uuid.UUID, name *string, inventory []byte) (*model.Assessment, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type AssessmentStore struct {
	db           *gorm.DB
	metricsCache *metrics.MetricsCache
}

// Make sure we conform to Assessment interface
var _ Assessment = (*AssessmentStore)(nil)

func NewAssessmentStore(db *gorm.DB) Assessment {
	return &AssessmentStore{
		db: db,
	}
}

func (a *AssessmentStore) WithMetricsCache(cache *metrics.MetricsCache) {
	a.metricsCache = cache
}

func (a *AssessmentStore) List(ctx context.Context, filter *AssessmentQueryFilter) (model.AssessmentList, error) {
	var assessments model.AssessmentList
	tx := a.getDB(ctx).Model(&assessments).Order("created_at DESC").Preload("Snapshots", func(db *gorm.DB) *gorm.DB {
		return db.Order("snapshots.created_at DESC")
	})

	if filter != nil {
		for _, fn := range filter.QueryFn {
			tx = fn(tx)
		}
	}

	result := tx.Find(&assessments)
	if result.Error != nil {
		return nil, result.Error
	}
	return assessments, nil
}

func (a *AssessmentStore) Get(ctx context.Context, id uuid.UUID) (*model.Assessment, error) {
	var assessment model.Assessment
	result := a.getDB(ctx).Preload("Snapshots", func(db *gorm.DB) *gorm.DB {
		return db.Order("snapshots.created_at DESC")
	}).First(&assessment, "id = ?", id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrRecordNotFound
		}
		return nil, result.Error
	}
	return &assessment, nil
}

func (a *AssessmentStore) Create(ctx context.Context, assessment model.Assessment, inventory []byte) (*model.Assessment, error) {
	// Create the assessment first
	result := a.getDB(ctx).Clauses(clause.Returning{}).Create(&assessment)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return nil, ErrDuplicateKey
		}
		return nil, result.Error
	}

	// Create the initial snapshot with the inventory
	snapshot := model.Snapshot{
		AssessmentID: assessment.ID,
		Inventory:    inventory,
		Version:      uint(util.GetInventoryVersion(inventory)),
	}

	if err := a.getDB(ctx).Create(&snapshot).Error; err != nil {
		return nil, err
	}

	// Update metrics cache
	if a.metricsCache != nil {
		var inv api.Inventory
		if err := json.Unmarshal(inventory, &inv); err == nil {
			a.metricsCache.ApplyCreate(assessment, inv)
		} else {
			zap.S().Debugw("failed to parse inventory for metrics", "error", err)
		}
	}

	// Return the assessment with snapshots loaded
	return a.Get(ctx, assessment.ID)
}

func (a *AssessmentStore) Update(ctx context.Context, assessmentID uuid.UUID, name *string, inventory []byte) (*model.Assessment, error) {
	// Check if assessment exists
	var assessment model.Assessment
	if err := a.getDB(ctx).First(&assessment, "id = ?", assessmentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	// Update assessment name if provided
	if name != nil {
		assessment.Name = *name
	}

	if inventory != nil {
		snapshot := model.Snapshot{
			AssessmentID: assessmentID,
			Inventory:    inventory,
			Version:      uint(util.GetInventoryVersion(inventory)),
		}

		if err := a.getDB(ctx).Create(&snapshot).Error; err != nil {
			return nil, err
		}
	}

	now := time.Now()
	assessment.UpdatedAt = &now
	if err := a.getDB(ctx).Model(&assessment).Updates(&assessment).Error; err != nil {
		return nil, err
	}

	// Return the updated assessment with snapshots
	return &assessment, nil
}

func (a *AssessmentStore) Delete(ctx context.Context, id uuid.UUID) error {
	// Fetch assessment + snapshot BEFORE deleting (for metrics)
	var assessment *model.Assessment
	var inv api.Inventory

	if a.metricsCache != nil {
		var err error
		assessment, err = a.Get(ctx, id)
		if err != nil && !errors.Is(err, ErrRecordNotFound) {
			return err
		}

		// Parse inventory from latest snapshot
		if assessment != nil && len(assessment.Snapshots) > 0 {
			json.Unmarshal(assessment.Snapshots[0].Inventory, &inv)
		}
	}

	// Existing delete operation
	result := a.getDB(ctx).Unscoped().Delete(&model.Assessment{}, "id = ?", id.String())
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	// Update metrics cache
	if a.metricsCache != nil && assessment != nil {
		a.metricsCache.ApplyDelete(*assessment, inv)
	}

	return nil
}

func (a *AssessmentStore) getDB(ctx context.Context) *gorm.DB {
	tx := FromContext(ctx)
	if tx != nil {
		return tx
	}
	return a.db
}
