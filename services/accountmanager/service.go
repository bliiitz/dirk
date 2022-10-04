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
	"context"

	"github.com/bliiitz/dirk/core"
	"github.com/bliiitz/dirk/services/checker"
)

// Service is the account manager service.
type Service interface {
	// Generate generates a new account.
	Generate(ctx context.Context,
		credentials *checker.Credentials,
		account string,
		passphrase []byte,
		participants uint32,
		signingThreshold uint32,
	) (
		core.Result,
		[]byte,
		[]*core.Endpoint,
		error,
	)

	// Unlock unlocks an account.
	Unlock(ctx context.Context,
		credentials *checker.Credentials,
		account string,
		passphrase []byte,
	) (
		core.Result,
		error,
	)
	// Lock locks an account.
	Lock(ctx context.Context,
		credentials *checker.Credentials,
		account string,
	) (
		core.Result,
		error,
	)
}
