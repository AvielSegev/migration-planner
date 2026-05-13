package metrics

import (
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	api "github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/store/model"
	"go.uber.org/zap"
)

// MetricsCache manages cached inventory statistics
type MetricsCache struct {
	stats atomic.Pointer[model.InventoryStats]
	mu    sync.Mutex // Protects internal state maps

	// Internal state for incremental updates
	assessmentOrgIDs  map[uuid.UUID]string
	assessmentSources map[uuid.UUID]string
}

// NewMetricsCache creates a new metrics cache
func NewMetricsCache() *MetricsCache {
	cache := &MetricsCache{
		assessmentOrgIDs:  make(map[uuid.UUID]string),
		assessmentSources: make(map[uuid.UUID]string),
	}

	// Initialize with empty stats
	emptyStats := model.InventoryStats{
		Vms: model.VmStats{
			TotalByCustomer: make(map[string]int),
			TotalByOS:       make(map[string]int),
		},
		TotalAssessmentsByCustomerBySource: make(map[string]model.CustomerAssessments),
		Storage:                            []model.StorageCustomerStats{},
	}
	cache.stats.Store(&emptyStats)

	return cache
}

// Initialize sets the initial statistics
func (mc *MetricsCache) Initialize(initStats model.InventoryStats) {
	mc.stats.Store(&initStats)

	zap.S().Named("metrics_cache").Debugw("metrics cache initialized",
		"vms", initStats.Vms.Total,
		"customers", initStats.TotalCustomers,
		"inventories", initStats.TotalInventories)
}

// GetStats returns the current cached statistics
func (mc *MetricsCache) GetStats() model.InventoryStats {
	ptr := mc.stats.Load()
	if ptr == nil {
		return model.InventoryStats{}
	}
	return *ptr
}

// ApplyCreate handles assessment creation
func (mc *MetricsCache) ApplyCreate(assessment model.Assessment, inventory api.Inventory) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	currentStats := mc.stats.Load()
	if currentStats == nil {
		return
	}

	orgID := model.DetermineOrgID(assessment.Username, assessment.OrgID)

	// Extract inventory stats
	vmCount := 0
	osBreakdown := make(map[string]int)
	storageByType := make(map[string]int)

	if inventory.Vcenter != nil {
		vmCount = inventory.Vcenter.Vms.Total

		if inventory.Vcenter.Vms.OsInfo != nil {
			for osType, osInfo := range *inventory.Vcenter.Vms.OsInfo {
				osBreakdown[osType] = osInfo.Count
			}
		}

		for _, ds := range inventory.Vcenter.Infra.Datastores {
			storageByType[ds.Type] += ds.TotalCapacityGB
		}
	}

	// Update VM stats
	currentStats.Vms.Total += vmCount
	currentStats.Vms.TotalByCustomer[orgID] += vmCount

	for osType, count := range osBreakdown {
		currentStats.Vms.TotalByOS[osType] += count
	}

	// Update OS stats (total unique OS types)
	currentStats.Os.Total = len(currentStats.Vms.TotalByOS)

	// Update inventory count
	currentStats.TotalInventories++

	// Update customer assessments

	customerAssessment := currentStats.TotalAssessmentsByCustomerBySource[orgID]
	if assessment.SourceType == model.SourceTypeAgent {
		customerAssessment.AgentCount++
	} else if assessment.SourceType == model.SourceTypeRvtools {
		customerAssessment.RvToolCount++
	}
	currentStats.TotalAssessmentsByCustomerBySource[orgID] = customerAssessment

	// Update customer count (count unique orgIDs)
	customers := make(map[string]struct{})
	for org := range currentStats.TotalAssessmentsByCustomerBySource {
		customers[org] = struct{}{}
	}
	currentStats.TotalCustomers = len(customers)

	// Update storage stats
	mc.updateStorageStats(currentStats, orgID, storageByType, true)

	// Store assessment metadata
	mc.assessmentOrgIDs[assessment.ID] = orgID
	mc.assessmentSources[assessment.ID] = assessment.SourceType
}

// ApplyDelete handles assessment deletion
func (mc *MetricsCache) ApplyDelete(assessment model.Assessment, inventory api.Inventory) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	currentStats := mc.stats.Load()
	if currentStats == nil {
		return
	}

	// Lookup metadata
	orgID, exists := mc.assessmentOrgIDs[assessment.ID]
	if !exists {
		zap.S().Named("metrics_cache").Warnw("deleting unknown assessment",
			"assessment_id", assessment.ID)
		return
	}

	sourceType := mc.assessmentSources[assessment.ID]

	// Extract inventory stats (same as create)
	vmCount := 0
	osBreakdown := make(map[string]int)
	storageByType := make(map[string]int)

	if inventory.Vcenter != nil {
		vmCount = inventory.Vcenter.Vms.Total

		if inventory.Vcenter.Vms.OsInfo != nil {
			for osType, osInfo := range *inventory.Vcenter.Vms.OsInfo {
				osBreakdown[osType] = osInfo.Count
			}
		}

		for _, ds := range inventory.Vcenter.Infra.Datastores {
			storageByType[ds.Type] += ds.TotalCapacityGB
		}
	}

	// Decrement VM stats
	currentStats.Vms.Total -= vmCount
	if currentStats.Vms.Total < 0 {
		zap.S().Named("metrics_cache").Warnw("clamped negative VM total")
		currentStats.Vms.Total = 0
	}

	currentStats.Vms.TotalByCustomer[orgID] -= vmCount
	if currentStats.Vms.TotalByCustomer[orgID] <= 0 {
		delete(currentStats.Vms.TotalByCustomer, orgID)
	}

	for osType, count := range osBreakdown {
		currentStats.Vms.TotalByOS[osType] -= count
		if currentStats.Vms.TotalByOS[osType] <= 0 {
			delete(currentStats.Vms.TotalByOS, osType)
		}
	}

	// Update OS stats
	currentStats.Os.Total = len(currentStats.Vms.TotalByOS)

	// Decrement inventory count
	currentStats.TotalInventories--
	if currentStats.TotalInventories < 0 {
		zap.S().Named("metrics_cache").Warnw("clamped negative inventory count")
		currentStats.TotalInventories = 0
	}

	// Update customer assessments
	customerAssessment := currentStats.TotalAssessmentsByCustomerBySource[orgID]
	if sourceType == model.SourceTypeAgent {
		customerAssessment.AgentCount--
	} else if sourceType == model.SourceTypeRvtools {
		customerAssessment.RvToolCount--
	}

	// Remove customer if no more assessments
	if customerAssessment.AgentCount <= 0 && customerAssessment.RvToolCount <= 0 {
		delete(currentStats.TotalAssessmentsByCustomerBySource, orgID)
	} else {
		currentStats.TotalAssessmentsByCustomerBySource[orgID] = customerAssessment
	}

	// Update customer count
	currentStats.TotalCustomers = len(currentStats.TotalAssessmentsByCustomerBySource)

	// Update storage stats
	mc.updateStorageStats(currentStats, orgID, storageByType, false)

	// Clean up metadata
	delete(mc.assessmentOrgIDs, assessment.ID)
	delete(mc.assessmentSources, assessment.ID)
}

// updateStorageStats updates storage statistics
func (mc *MetricsCache) updateStorageStats(stats *model.InventoryStats, orgID string, storageByType map[string]int, add bool) {
	// Find or create storage entry for this customer
	var customerStorage *model.StorageCustomerStats
	for i := range stats.Storage {
		if stats.Storage[i].Domain == orgID {
			customerStorage = &stats.Storage[i]
			break
		}
	}

	if customerStorage == nil {
		stats.Storage = append(stats.Storage, model.StorageCustomerStats{
			Domain:          orgID,
			TotalByProvider: make(map[string]int),
		})
		customerStorage = &stats.Storage[len(stats.Storage)-1]
	}

	// Update storage by type
	for storageType, capacity := range storageByType {
		if add {
			customerStorage.TotalByProvider[storageType] += capacity
		} else {
			customerStorage.TotalByProvider[storageType] -= capacity
			if customerStorage.TotalByProvider[storageType] < 0 {
				zap.S().Named("metrics_cache").Warnw("clamped negative storage metric",
					"org", orgID, "type", storageType)
				customerStorage.TotalByProvider[storageType] = 0
			}
		}
	}
}
