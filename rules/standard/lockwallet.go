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

package standard

import (
	"context"

	"github.com/bliiitz/dirk/rules"
	"github.com/opentracing/opentracing-go"
)

// OnLockWallet is called when a request to lock a wallet needs to be approved.
func (s *Service) OnLockWallet(ctx context.Context, metadata *rules.ReqMetadata, req *rules.LockWalletData) rules.Result {
	span, _ := opentracing.StartSpanFromContext(ctx, "rules.OnLockWallet")
	defer span.Finish()

	return rules.APPROVED
}
