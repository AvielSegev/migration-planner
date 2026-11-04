package mappers_test

import (
	"encoding/json"
	"testing"

	api "github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/handlers/v1alpha1/mappers"
	"github.com/kubev2v/migration-planner/internal/model"
)

func TestInventoryLegacyUpload(t *testing.T) {
	raw := []byte(`{
  "vcenter_id": "vc-1",
  "clusters": {
    "cluster-1": {
      "vcenter": {
        "id": "vc-1"
      },
      "infra": {
        "totalHosts": 2,
        "totalClusters": 1,
        "hostsPerCluster": [
          2
        ],
        "vmsPerCluster": [
          7
        ]
      },
      "vms": {
        "total": 7,
        "os": {
          "Linux": 7
        },
        "osInfo": {
          "Linux": {
            "count": 7,
            "supported": true
          }
        },
        "distributionByComplexity": {
          "1": 7
        },
        "complexityDistribution": {
          "1": {
            "vmCount": 7,
            "totalSizeTB": 1.5
          }
        },
        "nicCount": {
          "total": 7
        },
        "cpuCores": {
          "total": 14,
          "histogram": {
            "data": [
              7
            ],
            "minValue": 2,
            "step": 1
          }
        }
      }
    }
  }
}`)
	var incoming api.Inventory
	if err := json.Unmarshal(raw, &incoming); err != nil {
		t.Fatal(err)
	}
	domain := mappers.InventoryFromAPI(incoming)
	outgoing := mappers.InventoryToAPI(domain)
	if outgoing.VcenterId != "vc-1" || outgoing.Clusters["cluster-1"].Vms.Total != 7 {
		t.Fatalf("lost inventory data: %+v", outgoing)
	}
	encoded, err := json.Marshal(outgoing)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatal(err)
	}
	data := output["clusters"].(map[string]any)["cluster-1"].(map[string]any)
	vms := data["vms"].(map[string]any)
	for _, check := range []struct {
		object map[string]any
		keys   []string
	}{
		{data, []string{"vcenter"}},
		{data["infra"].(map[string]any), []string{"totalClusters", "hostsPerCluster", "vmsPerCluster"}},
		{vms, []string{"distributionByComplexity", "nicCount", "os"}},
		{vms["cpuCores"].(map[string]any), []string{"histogram"}},
	} {
		for _, key := range check.keys {
			if _, ok := check.object[key]; ok {
				t.Errorf("deprecated field %q in response", key)
			}
		}
	}
	summary := (*outgoing.Clusters["cluster-1"].Vms.ComplexityDistribution)["1"]
	if summary.VmCount != 7 || summary.TotalSizeTB != 1.5 {
		t.Fatalf("lost complexity distribution: %+v", summary)
	}
}

func TestLegacySourceDoesNotRequireDeprecatedVCenterObject(t *testing.T) {
	for _, id := range []string{"vc-1", ""} {
		t.Run(id, func(t *testing.T) {
			source := model.Source{
				Version: model.InventoryVersionV1,
				Inventory: &model.Inventory{
					VcenterId: id,
					Vcenter:   &model.InventoryData{Vms: model.VMs{Total: 7}},
				},
			}
			got, err := mappers.SourceToApi(source)
			if err != nil {
				t.Fatal(err)
			}
			if got.Inventory.VcenterId != id || got.Inventory.Vcenter.Vms.Total != 7 {
				t.Fatalf("lost legacy source data: %+v", got.Inventory)
			}
		})
	}
}
