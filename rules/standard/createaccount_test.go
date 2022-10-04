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

package standard_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/bliiitz/dirk/rules"
	standardrules "github.com/bliiitz/dirk/rules/standard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAccount(t *testing.T) {
	ctx := context.Background()
	base, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	testRules, err := standardrules.New(ctx,
		standardrules.WithStoragePath(base),
		standardrules.WithAdminIPs([]string{"1.2.3.4", "5.6.7.8"}),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		metadata *rules.ReqMetadata
		req      *rules.CreateAccountData
		res      rules.Result
	}{
		{
			name:     "Good",
			metadata: &rules.ReqMetadata{},
			req:      &rules.CreateAccountData{},
			res:      rules.APPROVED,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := testRules.OnCreateAccount(ctx, test.metadata, test.req)
			assert.Equal(t, test.res, res)
		})
	}
}
