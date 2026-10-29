package mappers_test

import (
	"testing"

	api "github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/handlers/v1alpha1/mappers"
	"github.com/kubev2v/migration-planner/internal/model"
	. "github.com/onsi/gomega"
)

func TestInventoryClusterCounts(t *testing.T) {
	zero, two := 0, 2
	for _, tc := range []struct {
		name  string
		count *int
	}{
		{name: "omitted"},
		{name: "zero", count: &zero},
		{name: "nonzero", count: &two},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("from API", func(t *testing.T) {
				g := NewWithT(t)
				data := api.InventoryData{Infra: api.Infra{TotalClusters: tc.count}}
				inv := mappers.InventoryFromAPI(api.Inventory{
					Vcenter:  &data,
					Clusters: map[string]api.InventoryData{"cluster-1": data},
				})
				g.Expect(inv.Vcenter.Infra.TotalClusters).To(Equal(tc.count))
				g.Expect(inv.Clusters["cluster-1"].Infra.TotalClusters).To(Equal(tc.count))
			})
			t.Run("to API", func(t *testing.T) {
				g := NewWithT(t)
				data := model.InventoryData{Infra: model.Infra{TotalClusters: tc.count}}
				inv := mappers.InventoryToAPI(model.Inventory{
					Vcenter:  &data,
					Clusters: map[string]model.InventoryData{"cluster-1": data},
				})
				g.Expect(inv.Vcenter.Infra.TotalClusters).To(Equal(tc.count))
				g.Expect(inv.Clusters["cluster-1"].Infra.TotalClusters).To(Equal(tc.count))
			})
		})
	}
}
