package helpers

import (
	"testing"

	"github.com/kubev2v/migration-planner/internal/model"
)

func TestAggregateVCenterID(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
		want string
	}{
		{"same vCenter", []string{"vc-1", "vc-1"}, "vc-1"},
		{"different vCenters", []string{"vc-1", "vc-2"}, ""},
		{"missing ID", []string{"vc-1", ""}, ""},
		{"no inventories", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventories := make([]model.AssessmentInventory, len(tc.ids))
			for i, id := range tc.ids {
				inventories[i].Inventory = model.Inventory{
					VcenterId: id,
					Vcenter:   &model.InventoryData{Vms: model.VMs{Total: 1}},
				}
			}
			got, err := Aggregate(inventories)
			if err != nil {
				t.Fatal(err)
			}
			if got.VcenterId != tc.want {
				t.Errorf("vCenter ID = %q, want %q", got.VcenterId, tc.want)
			}
		})
	}
}
