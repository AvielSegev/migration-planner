package e2e_utils

import (
	"context"
	"fmt"
	"net/url"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/vim25/types"
)

func CreateVsphereVM(ctx context.Context, endpoint, vmName, os string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid vSphere URL %q: %w", endpoint, err)
	}

	client, err := govmomi.NewClient(ctx, u, true)
	if err != nil {
		return fmt.Errorf("failed to connect to vSphere: %w", err)
	}
	defer client.Logout(ctx)

	finder := find.NewFinder(client.Client, true)
	dc, err := finder.DefaultDatacenter(ctx)
	if err != nil {
		return fmt.Errorf("cannot find default datacenter: %w", err)
	}
	finder.SetDatacenter(dc)

	rp, err := finder.DefaultResourcePool(ctx)
	if err != nil {
		return fmt.Errorf("cannot find default resource pool: %w", err)
	}

	folders, err := dc.Folders(ctx)
	if err != nil {
		return fmt.Errorf("cannot get datacenter folders: %w", err)
	}
	vmFolder := folders.VmFolder

	spec := types.VirtualMachineConfigSpec{
		Name:     vmName,
		NumCPUs:  1,
		MemoryMB: 1024,
		GuestId:  os,
	}

	task, err := vmFolder.CreateVM(ctx, spec, rp, nil)
	if err != nil {
		return fmt.Errorf("failed to start VM creation task: %w", err)
	}

	result, err := task.WaitForResult(ctx, nil)
	if err != nil {
		return fmt.Errorf("VM creation failed: %w", err)
	}

	moRef := result.Result.(types.ManagedObjectReference).Value
	fmt.Printf("VM %q created with MoRef %s\n", vmName, moRef)
	return nil
}
