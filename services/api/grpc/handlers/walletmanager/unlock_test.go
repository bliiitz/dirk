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

package walletmanager_test

import (
	context "context"
	"testing"

	"github.com/bliiitz/dirk/services/api/grpc/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

func TestUnlock(t *testing.T) {
	tests := []struct {
		name   string
		client string
		req    *pb.UnlockWalletRequest
		//		walletName string
		//		passphrase []byte
		err   string
		state pb.ResponseState
	}{
		{
			name:   "Missing",
			client: "client1",
			state:  pb.ResponseState_DENIED,
			err:    "no request specified",
		},
		{
			name:   "Empty",
			client: "client1",
			req:    &pb.UnlockWalletRequest{},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "WalletUnknown",
			client: "client1",
			req: &pb.UnlockWalletRequest{
				Wallet: "Unknown",
			},
			state: pb.ResponseState_DENIED,
		},
		{
			name:   "Good",
			client: "client1",
			req: &pb.UnlockWalletRequest{
				Wallet:     "Wallet 1",
				Passphrase: []byte("Wallet 1 passphrase"),
			},
			state: pb.ResponseState_SUCCEEDED,
		},
		{
			name:   "DeniedClient",
			client: "Deny this client",
			req: &pb.UnlockWalletRequest{
				Wallet:     "Wallet 1",
				Passphrase: []byte("Wallet 1 passphrase"),
			},
			state: pb.ResponseState_DENIED,
		},
		{
			name:   "PassphraseIncorrect",
			client: "client1",
			req: &pb.UnlockWalletRequest{
				Wallet:     "Wallet 1",
				Passphrase: []byte("Wallet 1 passphrase bad"),
			},
			state: pb.ResponseState_DENIED,
		},
	}

	handler, err := Setup()
	require.Nil(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), &interceptors.ClientName{}, test.client)
			resp, err := handler.Unlock(ctx, test.req)
			if test.err == "" {
				// Result expected.
				require.NoError(t, err)
				assert.Equal(t, test.state, resp.State)
			} else {
				// Error expected.
				assert.EqualError(t, err, test.err)
			}
		})
	}
}
