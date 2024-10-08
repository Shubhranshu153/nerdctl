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
	"testing"

	"github.com/containerd/nerdctl/v2/pkg/testutil"
)

func TestRemoveContainer(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	tID := testutil.Identifier(t)

	// ignore error
	base.Cmd("rm", tID, "-f").AssertOK()

	base.Cmd("run", "-d", "--name", tID, testutil.CommonImage, "sleep", "infinity").AssertOK()
	defer base.Cmd("rm", tID, "-f").AssertOK()
	base.Cmd("rm", tID).AssertFail()

	base.Cmd("kill", tID).AssertOK()
	base.Cmd("rm", tID).AssertOK()
}
