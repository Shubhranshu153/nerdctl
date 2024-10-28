package container

import (
	"testing"

	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/imgutil"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

// TestCreateSnapshotOpts tests the createSnapshotOpts function.
func TestCreateSnapshotOpts(t *testing.T) {
	tests := []struct {
		name               string
		id                 string
		image              imgutil.EnsuredImage
		uidMaps            []specs.LinuxIDMapping
		gidMaps            []specs.LinuxIDMapping
		supportsMultiRemap bool
		expectError        bool
	}{
		{
			name:  "Single remapping",
			id:    "container1",
			image: imgutil.EnsuredImage{},
			uidMaps: []specs.LinuxIDMapping{
				{HostID: 1000, Size: 1},
			},
			gidMaps: []specs.LinuxIDMapping{
				{HostID: 1000, Size: 1},
			},
			supportsMultiRemap: false,
			expectError:        false,
		},
		{
			name:  "Multi remapping with support",
			id:    "container2",
			image: imgutil.EnsuredImage{},
			uidMaps: []specs.LinuxIDMapping{
				{HostID: 1000, Size: 1},
				{HostID: 2000, Size: 1},
			},
			gidMaps: []specs.LinuxIDMapping{
				{HostID: 3000, Size: 1},
			},
			supportsMultiRemap: true,
			expectError:        false,
		},
		{
			name:  "Multi remapping without support",
			id:    "container3",
			image: imgutil.EnsuredImage{},
			uidMaps: []specs.LinuxIDMapping{
				{HostID: 1000, Size: 1},
				{HostID: 2000, Size: 1},
			},
			gidMaps: []specs.LinuxIDMapping{
				{HostID: 3000, Size: 1},
			},
			supportsMultiRemap: false,
			expectError:        true,
		},
		{
			name:               "Empty UID/GID maps",
			id:                 "container4",
			image:              imgutil.EnsuredImage{},
			uidMaps:            []specs.LinuxIDMapping{},
			gidMaps:            []specs.LinuxIDMapping{},
			supportsMultiRemap: false,
			expectError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := createSnapshotOpts(tt.id, tt.image, tt.uidMaps, tt.gidMaps, tt.supportsMultiRemap)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, opts)
			}
		})
	}
}

// TestGetContainerNameFromNetworkSlice tests the getContainerNameFromNetworkSlice function.
func TestGetContainerNameFromNetworkSlice(t *testing.T) {
	tests := []struct {
		name        string
		netOpts     types.NetworkOptions
		expected    string
		expectError bool
	}{
		{
			name: "Valid input with container name",
			netOpts: types.NetworkOptions{
				NetworkSlice: []string{"container:mycontainer"},
			},
			expected:    "mycontainer",
			expectError: false,
		},
		{
			name: "Invalid input with no colon separator",
			netOpts: types.NetworkOptions{
				NetworkSlice: []string{"container-mycontainer"},
			},
			expected:    "",
			expectError: true,
		},
		{
			name: "Empty NetworkSlice",
			netOpts: types.NetworkOptions{
				NetworkSlice: []string{""},
			},
			expected:    "",
			expectError: true,
		},
		{
			name: "Missing container name",
			netOpts: types.NetworkOptions{
				NetworkSlice: []string{"container:"},
			},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			containerName, err := getContainerNameFromNetworkSlice(tt.netOpts)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, containerName)
			}
		})
	}
}
