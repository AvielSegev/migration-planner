package mappers

import (
	"github.com/kubev2v/migration-planner/internal/model"
	"github.com/kubev2v/migration-planner/pkg/events/kafka"
)

func ToStreamerModel(inventory model.Inventory) kafka.Inventory {
	result := kafka.Inventory{
		CollectionTime: inventory.CollectionTime,
		CreatedAt:      inventory.CreatedAt,
		Id:             inventory.VcenterId,
	}

	if inventory.VcenterVersion != nil {
		result.VcenterVersion = *inventory.VcenterVersion
	}

	if inventory.Vcenter == nil {
		return result
	}

	infra := inventory.Vcenter.Infra
	result.Data.Infra.TotalHosts = infra.TotalHosts
	if infra.TotalDatacenters != nil {
		result.Data.Infra.TotalDatacenters = *infra.TotalDatacenters
	}

	for _, datastore := range infra.Datastores {
		result.Data.Infra.Datastores = append(result.Data.Infra.Datastores, kafka.Datastore{
			DiskId:          datastore.DiskId,
			HostId:          datastore.HostId,
			Model:           datastore.Model,
			TotalCapacityGB: datastore.TotalCapacityGB,
			Type:            datastore.Type,
			Vendor:          datastore.Vendor,
		})
	}

	if infra.Hosts != nil {
		for _, host := range *infra.Hosts {
			mapped := kafka.Host{
				Model:  host.Model,
				Vendor: host.Vendor,
			}
			if host.Id != nil {
				mapped.Id = *host.Id
			}
			result.Data.Infra.Hosts = append(result.Data.Infra.Hosts, mapped)
		}
	}

	for _, network := range infra.Networks {
		mapped := kafka.Network{
			Name:     network.Name,
			Type:     string(network.Type),
			VmsCount: network.VmsCount,
		}
		if network.Dvswitch != nil {
			mapped.Dvswitch = *network.Dvswitch
		}
		if network.VlanId != nil {
			mapped.VlanId = *network.VlanId
		}
		result.Data.Infra.Networks = append(result.Data.Infra.Networks, mapped)
	}

	vms := inventory.Vcenter.Vms
	result.Data.Vms.Total = vms.Total
	result.Data.Vms.TotalMigratable = vms.TotalMigratable
	if vms.OsInfo != nil {
		osInfo := make(map[string]kafka.OsInfo, len(*vms.OsInfo))
		for name, info := range *vms.OsInfo {
			osInfo[name] = kafka.OsInfo{Count: info.Count}
		}
		result.Data.Vms.OsInfo = &osInfo
	}

	return result
}
