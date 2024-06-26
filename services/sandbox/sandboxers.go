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

package sandbox

import (
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/sandbox"
	"github.com/containerd/containerd/services"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.ServicePlugin,
		ID:   services.SandboxControllersService,
		Requires: []plugin.Type{
			plugin.SandboxControllerPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			sandboxesRaw, err := ic.GetByType(plugin.SandboxControllerPlugin)
			if err != nil {
				return nil, err
			}
			sandboxers := make(map[string]sandbox.Controller)
			for name, srv := range sandboxesRaw {
				inst, err := srv.Instance()
				if err != nil {
					return nil, err
				}
				sandboxers[name] = inst.(sandbox.Controller)
			}
			return sandboxers, nil
		},
	})
}
