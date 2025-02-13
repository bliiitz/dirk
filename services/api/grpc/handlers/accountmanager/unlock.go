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

package accountmanager

import (
	context "context"
	"errors"

	"github.com/bliiitz/dirk/core"
	"github.com/bliiitz/dirk/services/api/grpc/handlers"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// Unlock unlocks an account.
func (h *Handler) Unlock(ctx context.Context, req *pb.UnlockAccountRequest) (*pb.UnlockAccountResponse, error) {
	if req == nil {
		log.Warn().Str("result", "denied").Msg("Request not specified")
		return nil, errors.New("no request specified")
	}

	log.Trace().Str("account", req.GetAccount()).Msg("Unlock account received")
	res := &pb.UnlockAccountResponse{}

	result, err := h.accountManager.Unlock(ctx, handlers.GenerateCredentials(ctx), req.Account, req.Passphrase)
	if err != nil {
		log.Error().Err(err).Msg("Unlock attempt resulted in error")
		res.State = pb.ResponseState_FAILED
	} else {
		switch result {
		case core.ResultSucceeded:
			res.State = pb.ResponseState_SUCCEEDED
		case core.ResultDenied:
			res.State = pb.ResponseState_DENIED
		case core.ResultFailed:
			res.State = pb.ResponseState_FAILED
		default:
			res.State = pb.ResponseState_UNKNOWN
		}
	}

	return res, nil
}
