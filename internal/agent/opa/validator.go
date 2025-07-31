package opa

import (
	"context"

	vspheremodel "github.com/kubev2v/forklift/pkg/controller/provider/model/vsphere"
	"github.com/kubev2v/migration-planner/internal/opa"
)

type AgentValidator struct {
	opa *opa.Validator
}

func DefaultAgentValidator() (*AgentValidator, error) {

	reader := opa.NewPolicyReader()

	policiesDir := reader.DiscoverPoliciesDirectory()

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

func (v *AgentValidator) Validate(ctx context.Context, vms *[]vspheremodel.VM) ([]vspheremodel.VM, error) {
	validatedVMs, err := v.opa.ValidateVMs(ctx, *vms)
	if err != nil {
		return *vms, err
	}

	return validatedVMs, nil
}
