// Copyright © 2020, 2021 Attestant Limited.
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

package prometheus

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a metrics service exposing metrics via prometheus.
type Service struct {
	accountManagerProcessTimer *prometheus.HistogramVec
	accountManagerRequests     *prometheus.CounterVec

	walletManagerProcessTimer *prometheus.HistogramVec
	walletManagerRequests     *prometheus.CounterVec

	listerProcessTimer prometheus.Histogram
	listerRequests     *prometheus.CounterVec

	signerProcessTimer *prometheus.HistogramVec
	signerRequests     *prometheus.CounterVec
}

// module-wide log.
var log zerolog.Logger

// New creates a new prometheus metrics service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "metrics").Str("impl", "prometheus").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{}

	if err := s.setupAccountManagerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up account manager metrics")
	}
	if err := s.setupWalletManagerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up wallet manager metrics")
	}
	if err := s.setupListerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up lister metrics")
	}
	if err := s.setupSignerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up signer metrics")
	}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(parameters.address, nil); err != nil {
			log.Warn().Str("metrics_listen_address", parameters.address).Err(err).Msg("Failed to run metrics server")
		}
	}()

	return s, nil
}

// Presenter returns the presenter for the events.
func (s *Service) Presenter() string {
	return "prometheus"
}
