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

package walletmanager

import (
	"errors"

	"github.com/bliiitz/dirk/services/process"
	"github.com/bliiitz/dirk/services/walletmanager"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel      zerolog.Level
	walletManager walletmanager.Service
	process       process.Service
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(*parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithWalletManager sets the wallet manager service for the module.
func WithWalletManager(walletManager walletmanager.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.walletManager = walletManager
	})
}

// WithProcess sets the process service for the module.
func WithProcess(process process.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.process = process
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.walletManager == nil {
		return nil, errors.New("no wallet manager specified")
	}
	if parameters.process == nil {
		return nil, errors.New("no process specified")
	}

	return &parameters, nil
}
