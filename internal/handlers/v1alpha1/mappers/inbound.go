package mappers

import (
	"encoding/json"
	"fmt"
	"github.com/kubev2v/migration-planner/internal/handlers/validator"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/auth"
	"github.com/kubev2v/migration-planner/internal/model"
	"github.com/kubev2v/migration-planner/internal/service/mappers"
	store "github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/internal/util"
)

// mapLabels converts API labels to map[string]string
func mapLabels(apiLabels *[]v1alpha1.Label) map[string]string {
	if apiLabels == nil {
		return nil
	}
	labels := make(map[string]string, len(*apiLabels))
	for _, label := range *apiLabels {
		labels[label.Key] = label.Value
	}
	return labels
}

// mapProxyFields extracts proxy fields from API proxy struct
func mapProxyFields(proxy *v1alpha1.AgentProxy) (httpUrl, httpsUrl, noProxy string) {
	if proxy == nil {
		return "", "", ""
	}

	return util.DerefString(proxy.HttpUrl),
		util.DerefString(proxy.HttpsUrl),
		util.DerefString(proxy.NoProxy)
}

// mapProxyFieldsForUpdate extracts proxy fields for update form (returns pointers).
// When proxy is present, nil fields mean "clear" (not "skip"), matching create-path semantics.
func mapProxyFieldsForUpdate(proxy *v1alpha1.AgentProxy) (httpUrl, httpsUrl, noProxy *string) {
	if proxy == nil {
		return nil, nil, nil
	}
	h := util.DerefString(proxy.HttpUrl)
	hs := util.DerefString(proxy.HttpsUrl)
	np := util.DerefString(proxy.NoProxy)
	return &h, &hs, &np
}

func mapIpv4Fields(vmnetwork *v1alpha1.VmNetwork) (ipAddress, subnetMask, defaultGateway, dns string) {
	if vmnetwork == nil || vmnetwork.Ipv4 == nil {
		return "", "", "", ""
	}

	return vmnetwork.Ipv4.IpAddress, vmnetwork.Ipv4.SubnetMask, vmnetwork.Ipv4.DefaultGateway, vmnetwork.Ipv4.Dns
}

func SourceFormApi(resource v1alpha1.SourceCreate) mappers.SourceCreateForm {
	httpUrl, httpsUrl, noProxy := mapProxyFields(resource.Proxy)
	network := resource.VmNetwork
	if network == nil {
		network = resource.Network
	}
	ipAddress, subnetMask, defaultGateway, dns := mapIpv4Fields(network)

	form := mappers.SourceCreateForm{
		Name:              string(resource.Name),
		Labels:            mapLabels(resource.Labels),
		HttpUrl:           httpUrl,
		HttpsUrl:          httpsUrl,
		NoProxy:           noProxy,
		IpAddress:         ipAddress,
		SubnetMask:        subnetMask,
		DefaultGateway:    defaultGateway,
		Dns:               dns,
		EnableProxy:       resource.EnableProxy,
		NetworkConfigType: (*string)(resource.NetworkConfigType),
	}

	if resource.SshPublicKey != nil {
		form.SshPublicKey = string(*resource.SshPublicKey)
	}
	if resource.CertificateChain != nil {
		form.CertificateChain = string(*resource.CertificateChain)
	}

	return form
}

func SourceUpdateFormApi(resource v1alpha1.SourceUpdate) mappers.SourceUpdateForm {
	httpUrl, httpsUrl, noProxy := mapProxyFieldsForUpdate(resource.Proxy)

	form := mappers.SourceUpdateForm{
		HttpUrl:  httpUrl,
		HttpsUrl: httpsUrl,
		NoProxy:  noProxy,
	}

	network := resource.VmNetwork
	if network == nil {
		network = resource.Network
	}
	if network != nil && network.Ipv4 != nil {
		ipv4 := network.Ipv4
		form.IpAddress = &ipv4.IpAddress
		form.SubnetMask = &ipv4.SubnetMask
		form.DefaultGateway = &ipv4.DefaultGateway
		form.Dns = &ipv4.Dns
	}

	if resource.Name != nil {
		form.Name = (*string)(resource.Name)
	}
	if resource.SshPublicKey != nil {
		sshKey := string(*resource.SshPublicKey)
		form.SshPublicKey = &sshKey
	}
	if resource.CertificateChain != nil {
		certChain := string(*resource.CertificateChain)
		form.CertificateChain = &certChain
	}

	// Handle labels conversion - convert to simple form structure
	if resource.Labels != nil {
		labels := make([]mappers.Label, len(*resource.Labels))
		for i, label := range *resource.Labels {
			labels[i] = mappers.Label{Key: label.Key, Value: label.Value}
		}
		form.Labels = labels
	}

	form.EnableProxy = resource.EnableProxy
	form.NetworkConfigType = (*string)(resource.NetworkConfigType)

	return form
}

// Assessment-related mappers

func ClusterRequirementsRequestToForm(apiReq v1alpha1.ClusterRequirementsRequest) mappers.ClusterRequirementsRequestForm {
	// Map fields directly without applying defaults - preserve omission semantics
	form := mappers.ClusterRequirementsRequestForm{
		ClusterID:             apiReq.ClusterId,
		CpuOverCommitRatio:    string(apiReq.CpuOverCommitRatio),
		MemoryOverCommitRatio: string(apiReq.MemoryOverCommitRatio),
		WorkerNodeCPU:         apiReq.WorkerNodeCPU,
		WorkerNodeMemory:      apiReq.WorkerNodeMemory,

		// Optional fields - preserve nil if not provided
		WorkerNodeThreads:       apiReq.WorkerNodeThreads,
		HostedControlPlane:      apiReq.HostedControlPlane,
		ControlPlaneSchedulable: apiReq.ControlPlaneSchedulable,
		ControlPlaneCPU:         apiReq.ControlPlaneCPU,
		ControlPlaneMemory:      apiReq.ControlPlaneMemory,
		CompactMode:             apiReq.CompactMode,
	}

	// Convert ControlPlaneNodeCount from API type to int pointer
	if apiReq.ControlPlaneNodeCount != nil {
		nodeCount := int(*apiReq.ControlPlaneNodeCount)
		form.ControlPlaneNodeCount = &nodeCount
	}

	return form
}

func AssessmentFormToCreateForm(resource v1alpha1.AssessmentForm, user auth.User) mappers.AssessmentCreateForm {
	form := mappers.AssessmentCreateForm{
		ID:         uuid.New(),
		Name:       resource.Name,
		OrgID:      user.Organization,
		Username:   user.Username,
		SourceType: resource.SourceType,
	}

	// Set owner fields from user context (like username)
	if user.FirstName != "" {
		form.OwnerFirstName = &user.FirstName
	}
	if user.LastName != "" {
		form.OwnerLastName = &user.LastName
	}

	// Set source ID if provided
	if resource.SourceId != nil {
		form.SourceID = resource.SourceId
	}

	// Build inventories if inline inventory is provided
	if resource.Inventory != nil {
		if resource.Inventory.CreatedAt == nil {
			now := time.Now().UTC()
			resource.Inventory.CreatedAt = &now
		}
		inventory := InventoryFromAPI(*resource.Inventory)
		form.MainInventory = model.NewAssessmentInventory(uuid.New(), form.ID, resource.Name, model.InventoryVersionV2, false, inventory)
	}

	return form
}

func EnhancementDataAPIToModel(assessmentID uuid.UUID, data v1alpha1.EnhancementDataRequest) (*store.AssessmentEnhancementData, error) {
	m := &store.AssessmentEnhancementData{
		AssessmentID: assessmentID,
	}

	if data.DeployedEnvironment != nil {
		m.DeployedEnvEnvironment = store.TypedStringPtr(data.DeployedEnvironment.Environment)
	}

	if data.VmwareVersionCounts != nil {

		if err := validateManualCounts(
			manualCountInput{
				field:  "PerpetualLicensesCount",
				number: data.VmwareVersionCounts.PerpetualLicensesCount,
			},
			manualCountInput{
				field:  "CoresLicensingCount",
				number: data.VmwareVersionCounts.CoresLicensingCount,
			},
			manualCountInput{
				field:  "EnvironmentCount",
				number: data.VmwareVersionCounts.EnvironmentCount,
			},
			manualCountInput{
				field:  "OtherNodesCount",
				number: data.VmwareVersionCounts.OtherNodesCount,
			},
		); err != nil {
			return nil, err
		}

		m.VMwareVerPerpetualLicensesCount = data.VmwareVersionCounts.PerpetualLicensesCount
	}

	if data.ActiveEnvironments != nil {
		m.ActiveEnvEnvironments = store.TypedStringSlice(data.ActiveEnvironments.Environments)
	}

	if data.VmwareSubscription != nil {
		m.VMwareSubLevel = store.TypedStringSlice(data.VmwareSubscription.Level)
	}

	if data.VsphereCore != nil {
		m.VsphereVmEncryptionEnabled = data.VsphereCore.VmEncryptionEnabled
		m.VsphereVmEncryptionPolicy = data.VsphereCore.VmEncryptionPolicy
		m.VsphereSrmEnabled = data.VsphereCore.SrmEnabled
		m.VsphereNiocEnabled = data.VsphereCore.NiocEnabled
		m.VsphereNiocDetails = data.VsphereCore.NiocDetails
	}

	if data.Nsx != nil {
		m.NsxFeatures = store.TypedStringSlice(data.Nsx.Features)
	}

	if data.AriaOps != nil {
		m.AriaOpsFeatures = store.TypedStringSlice(data.AriaOps.Features)
	}

	if data.AriaAutomation != nil {
		m.AriaAutomationFeatures = store.TypedStringSlice(data.AriaAutomation.Features)
	}

	if data.AriaSecure != nil {
		m.AriaSecureFeatures = store.TypedStringSlice(data.AriaSecure.Features)
	}

	if data.CustomerDetails != nil {
		m.CustomerPhysicalLocationsCount = data.CustomerDetails.PhysicalLocationsCount
		m.CustomerTargetHardware = data.CustomerDetails.TargetHardware
	}

	return m
}

func InventoryToForm(inventory v1alpha1.Inventory) mappers.InventoryForm {
	return mappers.InventoryForm{
		Data: inventory,
	}
}

type manualCountInput struct {
	field  string
	number *json.Number
}

func validateManualCounts(inputs ...manualCountInput) error {
	for _, input := range inputs {
		if input.number == nil {
			continue
		}

		count, err := strconv.ParseInt(input.number.String(), 10, 32)
		if err != nil || count < 0 {

			if countErr := validator.ManualCountError(input.field); countErr != nil {
				return countErr
			}
			return err
		}
	}

	return nil
}
