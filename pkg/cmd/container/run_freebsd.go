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

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/nerdctl/v2/pkg/api/types"
	"github.com/containerd/nerdctl/v2/pkg/imgutil"
)

func WithoutRunMount() func(ctx context.Context, client oci.Client, c *containers.Container, s *oci.Spec) error {
	// not valid on freebsd
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error { return nil }
}

func setPlatformOptions(
	ctx context.Context,
	client *containerd.Client,
	id, uts string,
	internalLabels *internalLabels,
	options types.ContainerCreateOptions,
) ([]oci.SpecOpts, error) {
	return []oci.SpecOpts{}, nil
}

func generateSnapshotOption(id string, ensured *imgutil.EnsuredImage, options types.ContainerCreateOptions) (containerd.NewContainerOpts, error) {
	return containerd.WithNewSnapshot(id, ensured.Image), nil
}
