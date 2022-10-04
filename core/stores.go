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

package core

import (
	"context"
	"fmt"

	vault "github.com/bliiitz/go-eth2-wallet-store-vault"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	s3 "github.com/wealdtech/go-eth2-wallet-store-s3"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Stores defines all stores.
type Stores struct {
	Stores []*Store `mapstructure:"stores"`
}

// Store defines a single store.
type Store struct {
	Name                           string `mapstructure:"name"`
	Type                           string `mapstructure:"type"`
	Location                       string `mapstructure:"location"`
	Passphrase                     string `mapstructure:"passphrase"`
	ID                             string `mapstructure:"id"`
	VaultAddr                      string `mapstructure:"vault_addr"`
	VaultAuth                      string `mapstructure:"vault_auth"`
	VaultToken                     string `mapstructure:"vault_token"`
	VaultKubernetesAuthRole        string `mapstructure:"vault_kubernetes_auth_role"`
	VaultKubernetesAuthSATokenPath string `mapstructure:"vault_kubernetes_auth_sa_token_path"`
	VaultKubernetesAuth            string `mapstructure:"vault_kubernetes_auth"`
}

// InitStores initialises the stores from a configuration.
func InitStores(ctx context.Context, stores []*Store) ([]e2wtypes.Store, error) {
	if len(stores) == 0 {
		log.Warn().Msg("No stores configured; using default")
		return initDefaultStores(), nil
	}
	res := make([]e2wtypes.Store, 0, len(stores))
	for i, store := range stores {
		if store.Name == "" {
			return nil, fmt.Errorf("store %d has no name", i)
		}
		if store.Type == "" {
			return nil, fmt.Errorf("store %d has no type", i)
		}
		log.Trace().Str("Load store", store.Type).Msg("Adding store")
		switch store.Type {
		case "filesystem":
			log.Trace().Str("name", store.Name).Str("location", store.Location).Str("type", store.Type).Msg("Adding filesystem store")
			opts := make([]filesystem.Option, 0)
			if len(store.Passphrase) > 0 {
				opts = append(opts, filesystem.WithPassphrase([]byte(store.Passphrase)))
			}
			if store.Location != "" {
				opts = append(opts, filesystem.WithLocation(store.Location))
			}
			res = append(res, filesystem.New(opts...))
		case "s3":
			log.Trace().Str("name", store.Name).Msg("Adding S3 store")
			s3Store, err := s3.New(s3.WithPassphrase([]byte(store.Passphrase)))
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to access store %d", i))
			}
			res = append(res, s3Store)
		case "vault":
			log.Trace().Str("name", store.Name).Msg("Adding Vault store")
			vaultStore, err := vault.New(
				vault.WithPassphrase([]byte(store.Passphrase)),
				vault.WithID([]byte(store.ID)),
				vault.WithVaultAddr([]byte(store.VaultAddr)),
				vault.WithVaultAuth([]byte(store.VaultAuth)),
				vault.WithVaultToken([]byte(store.VaultToken)),
				vault.WithVaultKubernetesAuthRole([]byte(store.VaultKubernetesAuthRole)),
				vault.WithVaultKubernetesAuthSATokenPath([]byte(store.VaultKubernetesAuthSATokenPath)),
				vault.WithVaultKubernetesAuth([]byte(store.VaultKubernetesAuth)),
				vault.WithVaultAddr([]byte(store.VaultAddr)),
			)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to access store %d", i))
			}
			res = append(res, vaultStore)
		case "scratch":
			log.Trace().Msg("Adding scratch store")
			res = append(res, scratch.New())
		default:
			return nil, fmt.Errorf("store %d has unhandled type %q", i, store.Type)
		}
	}
	return res, nil
}

// initDefaultStores initialises the default stores.
func initDefaultStores() []e2wtypes.Store {
	res := make([]e2wtypes.Store, 1)
	res[0] = filesystem.New()
	return res
}
