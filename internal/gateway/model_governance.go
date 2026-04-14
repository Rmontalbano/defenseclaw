// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
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
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GovernanceVerdict is the result of a model/provider governance check.
type GovernanceVerdict struct {
	Allowed bool
	Reason  string
	Rule    string // "provider-allow", "provider-deny", "model-allow", "model-deny"
}

// ModelGovernor evaluates model and provider names against allow/deny
// lists. A nil governor always allows (feature disabled).
type ModelGovernor struct {
	mode         string
	blockMessage string
	logAllowed   bool

	providerAllow []string
	providerDeny  []string
	modelAllow    []string
	modelDeny     []string
}

// NewModelGovernor creates a governor from config. Returns nil when
// governance is disabled, so callers can nil-check for fast path.
func NewModelGovernor(cfg config.ModelGovernanceConfig) *ModelGovernor {
	if !cfg.Enabled {
		return nil
	}
	return &ModelGovernor{
		mode:          strings.ToLower(cfg.Mode),
		blockMessage:  cfg.BlockMessage,
		logAllowed:    cfg.LogAllowed,
		providerAllow: toLowerSlice(cfg.Providers.Allow),
		providerDeny:  toLowerSlice(cfg.Providers.Deny),
		modelAllow:    toLowerSlice(cfg.Models.Allow),
		modelDeny:     toLowerSlice(cfg.Models.Deny),
	}
}

// Check evaluates the provider and model against the configured rules.
// Provider is checked first, then model. Returns a verdict with reason.
func (g *ModelGovernor) Check(provider, model string) *GovernanceVerdict {
	if g == nil {
		return &GovernanceVerdict{Allowed: true}
	}

	provider = strings.ToLower(strings.TrimSpace(provider))
	model = strings.ToLower(strings.TrimSpace(model))

	if provider != "" {
		if len(g.providerAllow) > 0 {
			if !matchAny(provider, g.providerAllow) {
				return &GovernanceVerdict{
					Allowed: false,
					Rule:    "provider-allow",
					Reason:  fmt.Sprintf("provider %q is not in the allowed list", provider),
				}
			}
		}
		if matchAny(provider, g.providerDeny) {
			return &GovernanceVerdict{
				Allowed: false,
				Rule:    "provider-deny",
				Reason:  fmt.Sprintf("provider %q is explicitly denied", provider),
			}
		}
	}

	if model != "" {
		if len(g.modelAllow) > 0 {
			if !matchAny(model, g.modelAllow) {
				return &GovernanceVerdict{
					Allowed: false,
					Rule:    "model-allow",
					Reason:  fmt.Sprintf("model %q is not in the allowed list", model),
				}
			}
		}
		if matchAny(model, g.modelDeny) {
			return &GovernanceVerdict{
				Allowed: false,
				Rule:    "model-deny",
				Reason:  fmt.Sprintf("model %q is explicitly denied", model),
			}
		}
	}

	return &GovernanceVerdict{Allowed: true}
}

// IsMonitorOnly returns true when denials should be logged but not enforced.
func (g *ModelGovernor) IsMonitorOnly() bool {
	if g == nil {
		return false
	}
	return g.mode == "monitor"
}

// BlockMessage returns the user-facing denial message.
func (g *ModelGovernor) BlockMessage() string {
	if g == nil || g.blockMessage == "" {
		return "This model or provider is not authorized by your organization's policy."
	}
	return g.blockMessage
}

// LogAllowed returns whether allowed requests should be logged.
func (g *ModelGovernor) LogAllowed() bool {
	return g != nil && g.logAllowed
}

// matchAny returns true if value matches any pattern using glob (path.Match).
func matchAny(value string, patterns []string) bool {
	for _, p := range patterns {
		if matched, _ := path.Match(p, value); matched {
			return true
		}
		if p == value {
			return true
		}
	}
	return false
}

func toLowerSlice(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = strings.ToLower(strings.TrimSpace(v))
	}
	return out
}
