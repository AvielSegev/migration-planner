package mappers

import (
	"encoding/json"
	"fmt"

	"github.com/kubev2v/migration-planner/internal/model"
	storemodel "github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/internal/util"
	"gorm.io/gorm"
)

// SourceFromStore decodes the optional inventory at the persistence boundary.
func SourceFromStore(s storemodel.Source) (model.Source, error) {
	result := model.Source{
		ID:          s.ID,
		Name:        s.Name,
		VCenterID:   s.VCenterID,
		Username:    s.Username,
		OrgID:       s.OrgID,
		OnPremises:  s.OnPremises,
		UpdateType:  s.UpdateType,
		EmailDomain: s.EmailDomain,
		CreatedAt:   s.CreatedAt, UpdatedAt: s.UpdatedAt,
		ImageInfra: ImageInfraFromStore(s.ImageInfra),
	}
	if len(s.Inventory) > 0 {
		result.Version = uint(util.GetInventoryVersion(s.Inventory))
		inventory, err := UnmarshalInventory(s.Inventory, result.Version)
		if err != nil {
			return model.Source{}, fmt.Errorf("failed to decode source %s inventory: %w", s.ID, err)
		}
		result.Inventory = &inventory
	}
	if s.Agents != nil {
		result.Agents = make([]model.Agent, len(s.Agents))
		for i, agent := range s.Agents {
			result.Agents[i] = AgentFromStore(agent)
		}
	}
	if s.Labels != nil {
		result.Labels = make([]model.Label, len(s.Labels))
		for i, label := range s.Labels {
			result.Labels[i] = LabelFromStore(label)
		}
	}
	return result, nil
}

// SourceToStore serializes inventory and maps associations for persistence.
func SourceToStore(s model.Source) (storemodel.Source, error) {
	result := storemodel.Source{
		ID:          s.ID,
		Name:        s.Name,
		VCenterID:   s.VCenterID,
		Username:    s.Username,
		OrgID:       s.OrgID,
		OnPremises:  s.OnPremises,
		UpdateType:  s.UpdateType,
		EmailDomain: s.EmailDomain,
		Model:       gorm.Model{CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt},
		ImageInfra:  ImageInfraToStore(s.ImageInfra),
	}
	if s.Inventory != nil {
		raw, err := marshalSourceInventory(*s.Inventory, s.Version)
		if err != nil {
			return storemodel.Source{}, fmt.Errorf("failed to encode source %s inventory: %w", s.ID, err)
		}
		result.Inventory = raw
	}
	if s.Agents != nil {
		result.Agents = make([]storemodel.Agent, len(s.Agents))
		for i, agent := range s.Agents {
			result.Agents[i] = AgentToStore(agent)
		}
	}
	if s.Labels != nil {
		result.Labels = make([]storemodel.Label, len(s.Labels))
		for i, label := range s.Labels {
			result.Labels[i] = LabelToStore(label)
		}
	}
	return result, nil
}

// SourceSubsetInventoryFromStore decodes a stored subset inventory.
func SourceSubsetInventoryFromStore(s storemodel.SourceSubsetInventory) (model.SourceSubsetInventory, error) {
	version := uint(util.GetInventoryVersion(s.Inventory))
	inventory, err := UnmarshalInventory(s.Inventory, version)
	if err != nil {
		return model.SourceSubsetInventory{}, fmt.Errorf("failed to decode subset %q inventory: %w", s.Name, err)
	}
	return model.SourceSubsetInventory{
		ID:         s.ID,
		Name:       s.Name,
		SourceID:   s.SourceID,
		VCenterID:  s.VCenterID,
		VMsCount:   s.VMsCount,
		UpdateType: s.UpdateType,
		CreatedAt:  s.CreatedAt, UpdatedAt: s.UpdatedAt,
		Version: version, Inventory: inventory,
	}, nil
}

// SourceSubsetInventoryToStore serializes a domain subset inventory.
func SourceSubsetInventoryToStore(s model.SourceSubsetInventory) (storemodel.SourceSubsetInventory, error) {
	raw, err := marshalSourceInventory(s.Inventory, s.Version)
	if err != nil {
		return storemodel.SourceSubsetInventory{}, fmt.Errorf("failed to encode subset %q inventory: %w", s.Name, err)
	}
	return storemodel.SourceSubsetInventory{
		ID:         s.ID,
		Name:       s.Name,
		SourceID:   s.SourceID,
		VCenterID:  s.VCenterID,
		VMsCount:   s.VMsCount,
		UpdateType: s.UpdateType,
		Model:      gorm.Model{CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt},
		Inventory:  raw,
	}, nil
}

func marshalSourceInventory(inventory model.Inventory, version uint) ([]byte, error) {
	if version == model.InventoryVersionV1 {
		return json.Marshal(inventory.Vcenter)
	}
	return json.Marshal(inventory)
}

// AgentFromStore converts stored source metadata to domain values.
func AgentFromStore(s storemodel.Agent) model.Agent {
	return model.Agent{
		ID:         s.ID,
		Status:     s.Status,
		StatusInfo: s.StatusInfo,
		CredUrl:    s.CredUrl,
		Version:    s.Version,
		SourceID:   s.SourceID,
		CreatedAt:  s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

// AgentToStore converts source metadata to its persistence representation.
func AgentToStore(s model.Agent) storemodel.Agent {
	return storemodel.Agent{
		ID:         s.ID,
		Status:     s.Status,
		StatusInfo: s.StatusInfo,
		CredUrl:    s.CredUrl,
		Version:    s.Version,
		SourceID:   s.SourceID,
		Model:      gorm.Model{CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt},
	}
}

// ImageInfraFromStore converts stored source metadata to domain values.
func ImageInfraFromStore(s storemodel.ImageInfra) model.ImageInfra {
	return model.ImageInfra{
		SourceID:         s.SourceID,
		HttpProxyUrl:     s.HttpProxyUrl,
		HttpsProxyUrl:    s.HttpsProxyUrl,
		NoProxyDomains:   s.NoProxyDomains,
		CertificateChain: s.CertificateChain,
		SshPublicKey:     s.SshPublicKey,
		ImageTokenKey:    s.ImageTokenKey,
		IpAddress:        s.IpAddress,
		SubnetMask:       s.SubnetMask,
		DefaultGateway:   s.DefaultGateway,
		Dns:              s.Dns,
		AgentVersion:     s.AgentVersion,
		AgentToken:       s.AgentToken,
		CreatedAt:        s.CreatedAt, UpdatedAt: s.UpdatedAt,
		ID: s.ID,
	}
}

// ImageInfraToStore converts source metadata to its persistence representation.
func ImageInfraToStore(s model.ImageInfra) storemodel.ImageInfra {
	return storemodel.ImageInfra{
		SourceID:         s.SourceID,
		HttpProxyUrl:     s.HttpProxyUrl,
		HttpsProxyUrl:    s.HttpsProxyUrl,
		NoProxyDomains:   s.NoProxyDomains,
		CertificateChain: s.CertificateChain,
		SshPublicKey:     s.SshPublicKey,
		ImageTokenKey:    s.ImageTokenKey,
		IpAddress:        s.IpAddress,
		SubnetMask:       s.SubnetMask,
		DefaultGateway:   s.DefaultGateway,
		Dns:              s.Dns,
		AgentVersion:     s.AgentVersion,
		AgentToken:       s.AgentToken,
		Model:            gorm.Model{CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, ID: s.ID},
	}
}

// LabelFromStore converts stored source metadata to domain values.
func LabelFromStore(s storemodel.Label) model.Label {
	return model.Label{
		Key:      s.Key,
		Value:    s.Value,
		SourceID: s.SourceID,
	}
}

// LabelToStore converts source metadata to its persistence representation.
func LabelToStore(s model.Label) storemodel.Label {
	return storemodel.Label{
		Key:      s.Key,
		Value:    s.Value,
		SourceID: s.SourceID,
	}
}
