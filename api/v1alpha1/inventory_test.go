package v1alpha1

import (
	"encoding/json"
	"testing"
)

func TestInventoryIgnoresDeprecatedFields(t *testing.T) {
	raw := []byte(`{
		"vcenter_id": "vc-1", "clusters": {},
		"vcenter": {
			"vcenter": {"id": "vc-1"},
			"infra": {"totalHosts": 2, "totalClusters": 1, "hostsPerCluster": [2], "vmsPerCluster": [7]},
			"vms": {
				"total": 7,
				"distributionByComplexity": {"1": 7},
				"complexityDistribution": {"1": {"vmCount": 7, "totalSizeTB": 1.5}},
				"os": {"Linux": 7}, "osInfo": {"Linux": {"count": 7, "supported": true}},
				"nicCount": {"total": 7},
				"cpuCores": {"total": 14, "histogram": {"data": [7], "minValue": 2, "step": 1}}
			}
		}
	}`)
	var inv Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.VcenterId != "vc-1" || inv.Vcenter.Vms.Total != 7 || inv.Vcenter.Infra.TotalHosts != 2 {
		t.Fatalf("lost current inventory data: %+v", inv)
	}
	if got := (*inv.Vcenter.Vms.ComplexityDistribution)["1"]; got.VmCount != 7 || got.TotalSizeTB != 1.5 {
		t.Fatalf("lost enriched complexity data: %+v", got)
	}
	if got := (*inv.Vcenter.Vms.OsInfo)["Linux"]; got.Count != 7 || !got.Supported {
		t.Fatalf("lost OS info: %+v", got)
	}
	encoded, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatal(err)
	}
	data := output["vcenter"].(map[string]any)
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
			if _, present := check.object[key]; present {
				t.Errorf("deprecated field %q survived decoding and re-encoding", key)
			}
		}
	}
}

func TestInventorySchemaAcceptsDeprecatedFields(t *testing.T) {
	doc, err := GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	data := InventoryData{
		Infra: Infra{Datastores: []Datastore{}, Networks: []Network{}, HostPowerStates: map[string]int{}},
		Vms:   VMs{PowerStates: map[string]int{}, MigrationWarnings: MigrationIssues{}, NotMigratableReasons: MigrationIssues{}},
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var incoming map[string]any
	if err := json.Unmarshal(encoded, &incoming); err != nil {
		t.Fatal(err)
	}
	incoming["vcenter"] = map[string]any{"id": "vc-1"}
	incoming["infra"].(map[string]any)["totalClusters"] = 1
	incoming["infra"].(map[string]any)["hostsPerCluster"] = []any{2}
	incoming["infra"].(map[string]any)["vmsPerCluster"] = []any{7}
	for _, key := range []string{"distributionByComplexity", "nicCount", "os"} {
		incoming["vms"].(map[string]any)[key] = map[string]any{}
	}
	incoming["vms"].(map[string]any)["cpuCores"].(map[string]any)["histogram"] = map[string]any{"minValue": 1, "step": 1, "data": []any{7}}
	if err := doc.Components.Schemas["InventoryData"].Value.VisitJSON(incoming); err != nil {
		t.Fatalf("legacy fields rejected by request schema: %v", err)
	}
}
