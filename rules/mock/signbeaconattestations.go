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

	"github.com/bliiitz/dirk/rules"
)

// OnSignBeaconAttestations is called when a request to sign multiple beacon block attestations needs to be approved.
func (s *Service) OnSignBeaconAttestations(ctx context.Context,
	metadata []*rules.ReqMetadata,
	req []*rules.SignBeaconAttestationData,
) []rules.Result {
	results := make([]rules.Result, len(req))
	for i := range req {
		results[i] = rules.APPROVED
	}

	return results
}
