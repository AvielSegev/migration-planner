package mappers_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kubev2v/migration-planner/internal/model"
	"github.com/kubev2v/migration-planner/internal/store/mappers"
	storemodel "github.com/kubev2v/migration-planner/internal/store/model"
	"gorm.io/gorm"
)

func TestSourceInventoryPresence(t *testing.T) {
	for _, raw := range [][]byte{nil, {}} {
		source, err := mappers.SourceFromStore(storemodel.Source{Inventory: raw})
		if err != nil {
			t.Fatal(err)
		}
		if source.Inventory != nil {
			t.Fatal("source without stored inventory must have nil inventory")
		}
		stored, err := mappers.SourceToStore(source)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Inventory != nil {
			t.Fatal("absent inventory must remain absent after serialization")
		}
	}
	inventory := model.Inventory{Clusters: map[string]model.InventoryData{}}
	stored, err := mappers.SourceToStore(model.Source{Version: model.InventoryVersionV2, Inventory: &inventory})
	if err != nil {
		t.Fatal(err)
	}
	source, err := mappers.SourceFromStore(stored)
	if err != nil {
		t.Fatal(err)
	}
	if source.Inventory == nil || source.Inventory.Clusters == nil {
		t.Fatal("an empty inventory must remain present and structured")
	}
}

func TestSourceInventoryVersionRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		version uint
		raw     string
	}{
		{"legacy v1", model.InventoryVersionV1, `{"vcenter":{"id":"vc-1"},"vms":{"total":7},"infra":{"totalHosts":2}}`},
		{"v2", model.InventoryVersionV2, `{"vcenter_id":"vc-1","vcenter":{"vms":{"total":7},"infra":{"totalHosts":2}},"clusters":{"cluster-1":{"vms":{"total":3}}},"collection_time":"2026-09-20T10:30:00Z"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, err := mappers.SourceFromStore(storemodel.Source{Inventory: []byte(tc.raw)})
			if err != nil {
				t.Fatal(err)
			}
			if source.Version != tc.version || source.Inventory.VcenterId != "vc-1" || source.Inventory.Vcenter.Vms.Total != 7 {
				t.Fatalf("source inventory was not decoded correctly: %+v", source)
			}
			snapshot := model.NewAssessmentInventory(uuid.New(), uuid.New(), "main", source.Version, false, *source.Inventory)
			if snapshot.VMsCount != 7 || snapshot.HostsCount != 2 {
				t.Fatalf("incorrect snapshot counts: %+v", snapshot)
			}
			stored, err := mappers.SourceToStore(source)
			if err != nil {
				t.Fatal(err)
			}
			var shape map[string]json.RawMessage
			if err := json.Unmarshal(stored.Inventory, &shape); err != nil {
				t.Fatal(err)
			}
			_, wrapped := shape["vcenter_id"]
			if wrapped != (tc.version == model.InventoryVersionV2) {
				t.Fatalf("serialized inventory has wrong version shape: %s", stored.Inventory)
			}
			restored, err := mappers.SourceFromStore(stored)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(source.Inventory, restored.Inventory) || restored.Version != source.Version {
				t.Fatal("source inventory or version changed after round trip")
			}
			if tc.version == model.InventoryVersionV2 {
				want := time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)
				if source.Inventory.CollectionTime == nil || !source.Inventory.CollectionTime.Equal(want) || source.Inventory.Clusters["cluster-1"].Vms.Total != 3 {
					t.Fatal("v2 collection time or clusters were lost")
				}
			}
			subset, err := mappers.SourceSubsetInventoryFromStore(storemodel.SourceSubsetInventory{Inventory: []byte(tc.raw)})
			if err != nil {
				t.Fatal(err)
			}
			storedSubset, err := mappers.SourceSubsetInventoryToStore(subset)
			if err != nil {
				t.Fatal(err)
			}
			restoredSubset, err := mappers.SourceSubsetInventoryFromStore(storedSubset)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(subset, restoredSubset) || subset.Version != tc.version {
				t.Fatal("subset inventory or version changed after round trip")
			}
		})
	}
}

func TestSourceMetadataRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	sourceID := uuid.New()
	domain, agentVersion, token := "example.com", "1.2.3", "token"
	stored := storemodel.Source{
		Model: gorm.Model{CreatedAt: now, UpdatedAt: now},
		ID:    sourceID, Name: "source", Username: "user", OrgID: "org", VCenterID: "vc-1", OnPremises: true, UpdateType: "manual", EmailDomain: &domain,
		Agents:     []storemodel.Agent{{Model: gorm.Model{CreatedAt: now, UpdatedAt: now}, ID: uuid.New(), SourceID: sourceID, Status: "connected", StatusInfo: "ready", CredUrl: "url", Version: "v1"}},
		Labels:     []storemodel.Label{{Key: "env", Value: "test", SourceID: sourceID.String()}},
		ImageInfra: storemodel.ImageInfra{Model: gorm.Model{ID: 9, CreatedAt: now, UpdatedAt: now}, SourceID: sourceID, ImageTokenKey: "key", HttpProxyUrl: "http", HttpsProxyUrl: "https", NoProxyDomains: "localhost", CertificateChain: "cert", SshPublicKey: "ssh", IpAddress: "192.0.2.1", SubnetMask: "255.255.255.0", DefaultGateway: "192.0.2.254", Dns: "192.0.2.2", AgentVersion: &agentVersion, AgentToken: &token},
	}
	source, err := mappers.SourceFromStore(stored)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := mappers.SourceToStore(source)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored, restored) {
		t.Fatalf("source metadata changed after round trip:\nwant: %+v\ngot: %+v", stored, restored)
	}
	subset := storemodel.SourceSubsetInventory{Model: gorm.Model{CreatedAt: now, UpdatedAt: now}, ID: uuid.New(), SourceID: sourceID, Name: "subset", VCenterID: "", VMsCount: 0, UpdateType: "manual", Inventory: []byte(`{"vcenter_id":"vc-1","clusters":{}}`)}
	mapped, err := mappers.SourceSubsetInventoryFromStore(subset)
	if err != nil {
		t.Fatal(err)
	}
	restoredSubset, err := mappers.SourceSubsetInventoryToStore(mapped)
	if err != nil {
		t.Fatal(err)
	}
	restoredSubset.Inventory = subset.Inventory
	if !reflect.DeepEqual(subset, restoredSubset) {
		t.Fatal("subset metadata changed after round trip")
	}
}

func TestSourceMalformedInventories(t *testing.T) {
	for _, raw := range []string{`{"vms":`, `{"clusters":[],"vcenter_id":"vc-1"}`} {
		if _, err := mappers.SourceFromStore(storemodel.Source{Inventory: []byte(raw)}); err == nil {
			t.Fatalf("expected source decode error for %s", raw)
		}
		if _, err := mappers.SourceSubsetInventoryFromStore(storemodel.SourceSubsetInventory{Inventory: []byte(raw)}); err == nil {
			t.Fatalf("expected subset decode error for %s", raw)
		}
	}
}
