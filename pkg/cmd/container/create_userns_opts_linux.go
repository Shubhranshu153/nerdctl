/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package container

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/containerutil"
	"github.com/containerd/nerdctl/pkg/idutil/containerwalker"
	"github.com/containerd/nerdctl/pkg/imgutil"
	"github.com/containerd/nerdctl/pkg/netutil/nettype"
	nerdctlUserns "github.com/containerd/nerdctl/pkg/userns"
	"github.com/moby/moby/pkg/idtools"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	capabMultiRemapIDs = "multi-remap-ids"
)

// getUserNamespaceOpts generates spec opts and container opts for usernamespace
func getUserNamespaceOpts(
	ctx context.Context,
	client *containerd.Client,
	options *types.ContainerCreateOptions,
	ensuredImage imgutil.EnsuredImage,
	id string,
) ([]oci.SpecOpts, []containerd.NewContainerOpts, error) {

	idMapping, err := loadAndValidateIDMapping(options.Userns)
	if err != nil {
		return nil, nil, err
	}

	supportsMultiRemap, err := checkSnapshotterSupport(ctx, client, ensuredImage.Snapshotter)
	if err != nil {
		return nil, nil, err
	}

	uidMaps, gidMaps := convertMappings(idMapping)
	specOpts := []oci.SpecOpts{oci.WithUserNamespace(uidMaps, gidMaps)}

	snapshotOpts, err := createSnapshotOpts(id, ensuredImage, uidMaps, gidMaps, supportsMultiRemap)
	if err != nil {
		return nil, nil, err
	}

	return specOpts, snapshotOpts, nil
}

// getContainerUserNamespaceNetOpts retrieves the user namespace opts for the specified network container.
func getContainerUserNamespaceNetOpts(
	ctx context.Context,
	client *containerd.Client,
	netManager containerutil.NetworkOptionsManager,
) ([]oci.SpecOpts, error) {
	netOpts, err := netManager.InternalNetworkingOptionLabels(ctx)
	netType, err := nettype.Detect(netOpts.NetworkSlice)
	if err != nil {
		return nil, err
	} else if netType != nettype.Host {
		return []oci.SpecOpts{}, nil

	}

	containerName, err := getContainerNameFromNetworkSlice(netOpts)
	if err != nil {
		return nil, err
	}

	container, err := findContainer(ctx, client, containerName)
	if err != nil {
		return nil, err
	}

	if err := validateContainerStatus(ctx, container); err != nil {
		return nil, err
	}

	userNsPath, err := getUserNamespacePath(ctx, container)
	if err != nil {
		return nil, err
	}

	var userNameSpaceSpecOpts []oci.SpecOpts
	userNameSpaceSpecOpts = append(userNameSpaceSpecOpts, oci.WithLinuxNamespace(specs.LinuxNamespace{
		Type: specs.UserNamespace,
		Path: userNsPath,
	}))
	return userNameSpaceSpecOpts, nil
}

func convertIDMapToLinuxIDMapping(idMaps []idtools.IDMap) []specs.LinuxIDMapping {
	linuxIDMappings := make([]specs.LinuxIDMapping, len(idMaps))

	for i, idMap := range idMaps {
		linuxIDMappings[i] = specs.LinuxIDMapping{
			ContainerID: uint32(idMap.ContainerID),
			HostID:      uint32(idMap.HostID),
			Size:        uint32(idMap.Size),
		}
	}

	return linuxIDMappings
}

// withMultiRemapperLabels creates the labels used by any supporting snapshotter
// to shift the filesystem ownership with multiple ranges of maps
func withMultiRemapperLabels(uidmaps, gidmaps []specs.LinuxIDMapping) snapshots.Opt {
	idMap := nerdctlUserns.IDMap{
		UidMap: uidmaps,
		GidMap: gidmaps,
	}
	uidmapLabel, gidmapLabel := idMap.Marshal()
	return snapshots.WithLabels(map[string]string{
		snapshots.LabelSnapshotUIDMapping: uidmapLabel,
		snapshots.LabelSnapshotGIDMapping: gidmapLabel,
	})
}

// findContainer searches for a container by name and returns it if found.
func findContainer(
	ctx context.Context,
	client *containerd.Client,
	containerName string,
) (containerd.Container, error) {
	var container containerd.Container

	walker := &containerwalker.ContainerWalker{
		Client: client,
		OnFound: func(_ context.Context, found containerwalker.Found) error {
			if found.MatchCount > 1 {
				return fmt.Errorf("multiple containers found with prefix: %s", containerName)
			}
			container = found.Container
			return nil
		},
	}

	if n, err := walker.Walk(ctx, containerName); err != nil {
		return container, err
	} else if n == 0 {
		return container, fmt.Errorf("container not found: %s", containerName)
	}

	return container, nil
}

// validateContainerStatus checks if the container is running.
func validateContainerStatus(ctx context.Context, container containerd.Container) error {
	task, err := container.Task(ctx, nil)
	if err != nil {
		return err
	}

	status, err := task.Status(ctx)
	if err != nil {
		return err
	}

	if status.Status != containerd.Running {
		return fmt.Errorf("container %s is not running", container.ID())
	}

	return nil
}

// getUserNamespacePath returns the path to the container's user namespace.
func getUserNamespacePath(ctx context.Context, container containerd.Container) (string, error) {
	task, err := container.Task(ctx, nil)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("/proc/%d/ns/user", task.Pid()), nil
}

// Creates default snapshot options.
func createDefaultSnapshotOpts(id string, image imgutil.EnsuredImage) []containerd.NewContainerOpts {
	return []containerd.NewContainerOpts{
		containerd.WithNewSnapshot(id, image.Image),
	}
}

// Loads and validates the ID mapping from the given Userns.
func loadAndValidateIDMapping(userns string) (idtools.IdentityMapping, error) {
	idMapping, err := idtools.LoadIdentityMapping(userns)
	if err != nil {
		return idtools.IdentityMapping{}, err
	}
	if !validIDMapping(idMapping) {
		return idtools.IdentityMapping{}, errors.New("no valid UID/GID mappings found")
	}
	return idMapping, nil
}

// Checks if the snapshotter supports multi-remap IDs.
func checkSnapshotterSupport(
	ctx context.Context,
	client *containerd.Client,
	snapshotter string,
) (bool, error) {
	return snapshotterSupportsMultiRemap(ctx, client, snapshotter)
}

// Validates that both UID and GID mappings are available.
func validIDMapping(mapping idtools.IdentityMapping) bool {
	return len(mapping.UIDMaps) > 0 && len(mapping.GIDMaps) > 0
}

// Converts IDMapping into LinuxIDMapping structures.
func convertMappings(mapping idtools.IdentityMapping) ([]specs.LinuxIDMapping, []specs.LinuxIDMapping) {
	return convertIDMapToLinuxIDMapping(mapping.UIDMaps),
		convertIDMapToLinuxIDMapping(mapping.GIDMaps)
}

// Creates snapshot options based on ID mappings and snapshotter capabilities.
func createSnapshotOpts(
	id string,
	image imgutil.EnsuredImage,
	uidMaps, gidMaps []specs.LinuxIDMapping,
	supportsMultiRemap bool,
) ([]containerd.NewContainerOpts, error) {
	if !isValidMapping(uidMaps, gidMaps) {
		return nil, errors.New("snapshotter uidmap gidmap config invalid")
	}
	if isMultiMapping(uidMaps, gidMaps) {
		if supportsMultiRemap {
			return []containerd.NewContainerOpts{
				containerd.WithNewSnapshot(id, image.Image, withMultiRemapperLabels(uidMaps, gidMaps)),
			}, nil
		}
		return nil, errors.New("snapshotter doesn't support multiple UID/GID remapping")
	}
	return []containerd.NewContainerOpts{
		containerd.WithNewSnapshot(id, image.Image,
			containerd.WithRemapperLabels(0, uidMaps[0].HostID, 0, gidMaps[0].HostID, uidMaps[0].Size)),
	}, nil
}

// Checks if there are multiple mappings available.
func isMultiMapping(uidMaps, gidMaps []specs.LinuxIDMapping) bool {
	return len(uidMaps) > 1 || len(gidMaps) > 1
}

func isValidMapping(uidMaps, gidMaps []specs.LinuxIDMapping) bool {
	return len(uidMaps) > 0 && len(gidMaps) > 0
}

// Helper function to check if the snapshotter supports multi-remap IDs.
func snapshotterSupportsMultiRemap(
	ctx context.Context,
	client *containerd.Client,
	snapshotterName string,
) (bool, error) {
	caps, err := client.GetSnapshotterCapabilities(ctx, snapshotterName)
	if err != nil {
		return false, err
	}
	return hasCapability(caps, capabMultiRemapIDs), nil
}

// Checks if the given capability exists in the list.
func hasCapability(caps []string, capability string) bool {
	for _, cap := range caps {
		if cap == capability {
			return true
		}
	}
	return false
}

func getContainerNameFromNetworkSlice(netOpts types.NetworkOptions) (string, error) {

	netItems := strings.Split(netOpts.NetworkSlice[0], ":")
	if len(netItems) < 2 {
		return "", fmt.Errorf("container networking argument format must be 'container:<id|name>', got: %q", netOpts.NetworkSlice[0])
	} else if len(netItems[1]) == 0 {
		return "", fmt.Errorf("container name length invald, got length: 0")
	}
	containerName := netItems[1]

	return containerName, nil
}
