package kafka

import (
	"time"
)

type AssessmentEventPayload struct {
	Assessment AssessmentData `json:"assessment"`
}

type AssessmentData struct {
	ID          string     `json:"id"`
	Name        string     `json:"name,omitempty"`
	OrgID       string     `json:"org_id,omitempty"`
	OrgName     string     `json:"org_name,omitempty"`
	OrgType     string     `json:"org_type,omitempty"`
	Username    string     `json:"username,omitempty"`
	SourceType  string     `json:"source_type,omitempty"`
	PartnerID   *string    `json:"partner_id,omitempty"`
	PartnerName *string    `json:"partner_name,omitempty"`
	Location    *string    `json:"location,omitempty"`
	Inventory   Inventory  `json:"inventory,omitempty"`
	CreatedAt   time.Time  `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

type Inventory struct {
	CollectionTime *time.Time    `json:"collection_time"`
	CreatedAt      *time.Time    `json:"created_at,omitempty"`
	Data           InventoryData `json:"data"`
	Id             string        `json:"id"`
	VcenterVersion string        `json:"vcenter_version,omitempty"`
}

// InventoryData defines model for InventoryData.
type InventoryData struct {
	Infra Infra `json:"infra"`
	Vms   VMs   `json:"vms"`
}

type Infra struct {
	Datastores       []Datastore `json:"datastores,omitempty"`
	Hosts            []Host      `json:"hosts,omitempty"`
	Networks         []Network   `json:"networks,omitempty"`
	TotalDatacenters int         `json:"totalDatacenters,omitempty"`
	TotalHosts       int         `json:"totalHosts"`
}

type VMs struct {
	OsInfo          *map[string]OsInfo `json:"osInfo,omitempty"`
	Total           int                `json:"total"`
	TotalMigratable int                `json:"totalMigratable"`
}

type Network struct {
	Dvswitch string `json:"dvswitch,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	VlanId   string `json:"vlanId,omitempty"`
	VmsCount *int   `json:"vmsCount,omitempty"`
}

type Datastore struct {
	DiskId          string  `json:"diskId"`
	HostId          *string `json:"hostId"`
	Model           string  `json:"model"`
	TotalCapacityGB int     `json:"totalCapacityGB"`
	Type            string  `json:"type"`
	Vendor          string  `json:"vendor"`
}

type Host struct {
	Id     string `json:"id,omitempty"`
	Model  string `json:"model"`
	Vendor string `json:"vendor"`
}

type OsInfo struct {
	Count int `json:"count"`
}

func NewAssessmentCreatedPayload(data AssessmentData) AssessmentEventPayload {
	return AssessmentEventPayload{Assessment: data}
}

func NewAssessmentDeletedPayload(assessmentID string, deletedAt time.Time) AssessmentEventPayload {
	return AssessmentEventPayload{Assessment: AssessmentData{ID: assessmentID, DeletedAt: &deletedAt}}
}
