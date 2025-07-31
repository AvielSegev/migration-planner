package opa

import (
	"context"
	"encoding/json"
	vspheremodel "github.com/kubev2v/forklift/pkg/controller/provider/model/vsphere"
	"github.com/kubev2v/migration-planner/internal/opa"
)

type VMValidation struct {
	Result []vspheremodel.Concern `json:"result"`
}

type AgentValidator struct {
	opa *opa.Validator
}

func DefaultAgentValidator(policiesDir string) (*AgentValidator, error) {
	reader := opa.NewPolicyReader()

	policies, err := reader.ReadPolicies(policiesDir)
	if err != nil {
		return nil, err
	}

	opaValidator, err := opa.NewValidator(policies)
	if err != nil {
		return nil, err
	}

	return &AgentValidator{
		opa: opaValidator,
	}, nil
}

func (v *AgentValidator) Validate(ctx context.Context, vms *[]vspheremodel.VM) (*[]vspheremodel.VM, error) {
	var results []vspheremodel.VM

	for _, vm := range *vms {
		data, err := json.Marshal(vm)
		if err != nil {
			return nil, err
		}

		var vmMap map[string]interface{}
		if err := json.Unmarshal(data, &vmMap); err != nil {
			return nil, err
		}

		concerns, err := v.opa.ValidateConcerns(ctx, vmMap)
		if err != nil {
			return nil, err
		}

		concernsData, err := json.Marshal(concerns)
		if err != nil {
			return nil, err
		}

		var vmValidation VMValidation

		if err = json.Unmarshal(concernsData, &vmValidation); err != nil {
			return nil, err
		}

		for _, c := range vmValidation.Result {
			vm.Concerns = append(vm.Concerns, vspheremodel.Concern{Id: c.Id, Label: c.Label, Assessment: c.Assessment, Category: c.Category})
		}
		results = append(results, vm)
	}

	return &results, nil
}
