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

package static_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/bliiitz/dirk/services/checker"
	"github.com/bliiitz/dirk/services/checker/static"
	"github.com/bliiitz/dirk/services/metrics"
	"github.com/bliiitz/dirk/services/metrics/prometheus"
	"github.com/bliiitz/dirk/services/ruler"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	monitor, err := prometheus.New(ctx, prometheus.WithAddress("localhost:11111"))
	require.NoError(t, err)

	tests := []struct {
		name        string
		permissions map[string][]*checker.Permissions
		monitor     metrics.CheckerMonitor
		err         string
	}{
		{
			name: "Nil",
		},
		{
			name: "CertInfoNoPermissions",
			permissions: map[string][]*checker.Permissions{
				"client-01": nil,
			},
			err: "problem with parameters: client client-01 requires at least one permission",
		},
		{
			name: "CertInfoEmptyPath",
			permissions: map[string][]*checker.Permissions{
				"client-01": {{}},
			},
			err: "problem with parameters: invalid account path ",
		},
		{
			name: "CertInfoBadWallet",
			permissions: map[string][]*checker.Permissions{
				"client-01": {{Path: "/foo"}},
			},
			err: "problem with parameters: invalid account path /foo",
		},
		{
			name: "CertInfoInvalidWallet",
			permissions: map[string][]*checker.Permissions{
				"client-01": {{Path: "**/foo"}},
			},
			err: "problem with parameters: invalid wallet regex **",
		},
		{
			name: "CertInfoInvalidAccount",
			permissions: map[string][]*checker.Permissions{
				"client-01": {{Path: "foo/**"}},
			},
			err: "problem with parameters: invalid account regex **",
		},
		{
			name:    "Good",
			monitor: monitor,
			permissions: map[string][]*checker.Permissions{
				"client-01": {{Path: "foo"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := static.New(context.Background(),
				static.WithPermissions(test.permissions),
				static.WithMonitor(test.monitor))
			if test.err == "" {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	service, err := static.New(context.Background(),
		static.WithLogLevel(zerolog.Disabled),
		static.WithPermissions(map[string][]*checker.Permissions{
			// client1 only allows signing for Wallet1
			"client1": {
				{
					Path:       "Wallet1",
					Operations: []string{"Sign"},
				},
			},
		}),
	)
	require.Nil(t, err)

	tests := []struct {
		name        string
		credentials *checker.Credentials
		account     string
		operation   string
		result      bool
	}{
		{
			name:        "Empty",
			credentials: nil,
			account:     "",
			result:      false,
		},
		{
			name:        "NoClient",
			credentials: &checker.Credentials{},
			account:     "",
			result:      false,
		},
		{
			name:        "EmptyAccount",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "",
			result:      false,
		},
		{
			name:        "WalletOnlyAccount",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "Wallet1",
			result:      false,
		},
		{
			name:        "AccountOnlyAccount",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "/valid",
			result:      false,
		},
		{
			name:        "WalletMissing",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "/valid",
			operation:   "Sign",
			result:      false,
		},
		{
			name:        "AccountOnlyAccount",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "/valid",
			result:      false,
		},
		{
			name:        "WalletOnlyAccountTrailingSlash",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "Wallet1/",
			result:      false,
		},
		{
			name:        "UnknownClient",
			credentials: &checker.Credentials{Client: "clientx"},
			account:     "Wallet1/valid",
			result:      false,
		},
		{
			name:        "UnknownWallet",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "Wallet2/valid",
			result:      false,
		},
		{
			name:        "MissingOperation",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "Wallet1/valid",
			result:      false,
		},
		{
			name:        "BadOperation",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "Wallet1/valid",
			operation:   "Bad",
			result:      false,
		},
		{
			name:        "Valid",
			credentials: &checker.Credentials{Client: "client1"},
			account:     "Wallet1/valid",
			operation:   "Sign",
			result:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := service.Check(context.Background(), test.credentials, test.account, test.operation)
			assert.Equal(t, test.result, result)
		})
	}
}

func TestLists(t *testing.T) {
	service, err := static.New(context.Background(),
		static.WithLogLevel(zerolog.Disabled),
		static.WithPermissions(map[string][]*checker.Permissions{
			// client1 only allows signing for Wallet1.
			"client1": {
				{
					Path:       "Wallet1",
					Operations: []string{"Sign"},
				},
			},
			// client2 allows signing for Wallet1 and Wallet 2.
			"client2": {
				{
					Path:       "Wallet1",
					Operations: []string{"Sign"},
				},
				{
					Path:       "Wallet2",
					Operations: []string{"Sign"},
				},
			},
			// client3 allows everything but signing for wallet 1.
			"client3": {
				{
					Path:       "Wallet1",
					Operations: []string{"~Sign", "All"},
				},
			},
			// client4 has an explicit none.
			"client4": {
				{
					Path:       "Wallet1",
					Operations: []string{"None", "All"},
				},
			},
		}),
	)
	require.Nil(t, err)

	tests := []struct {
		name      string
		account   string
		operation string
		results   []bool
	}{
		{
			name:    "Nil",
			results: []bool{false, false, false, false},
		},
		{
			name:      "SignWallet1",
			account:   "Wallet1/Account1",
			operation: ruler.ActionSign,
			results:   []bool{true, true, false, false},
		},
		{
			name:      "SignWallet2",
			account:   "Wallet2/Account1",
			operation: ruler.ActionSign,
			results:   []bool{false, true, false, false},
		},
		{
			name:      "AccessAccountsWallet1",
			account:   "Wallet1/Account1",
			operation: ruler.ActionAccessAccount,
			results:   []bool{false, false, true, false},
		},
	}

	clients := []string{"client1", "client2", "client3", "client4"}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i := range clients {
				t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
					credentials := &checker.Credentials{
						Client: clients[i],
					}
					result := service.Check(context.Background(), credentials, test.account, test.operation)
					assert.Equal(t, test.results[i], result)
				})
			}
		})
	}
}
