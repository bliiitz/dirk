// Copyright © 2020 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mock

import (
	"context"

	"github.com/bliiitz/dirk/services/checker"
	static "github.com/bliiitz/dirk/services/checker/static"
)

// New creates a new mock checker that will deny clients called 'Deny this client' and any accounts starting with 'Deny'.
func New() (checker.Service, error) {
	permissions := map[string][]*checker.Permissions{
		"Deny this client": {
			{
				Path:       ".*",
				Operations: []string{"None"},
			},
		},
		"client1": {
			{
				Path:       ".*/Deny.*",
				Operations: []string{"None"},
			},
			{
				Path:       ".*",
				Operations: []string{"All"},
			},
		},
	}
	return static.New(context.Background(),
		static.WithPermissions(permissions),
	)
}
