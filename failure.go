// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

import "github.com/go-ruby-rack/rack"

// FailureEndpoint is the default on_failure handler — OmniAuth::FailureEndpoint.
// It reads the failure context that fail! stored in the env and either
// propagates the error (raise_out!) or redirects the browser to the failure
// path `<prefix>/failure?message=<key>&strategy=<name>`.
type FailureEndpoint struct {
	env    rack.Env
	config *Config
}

// NewFailureEndpoint wraps env and config for a single failure resolution.
func NewFailureEndpoint(env rack.Env, config *Config) *FailureEndpoint {
	return &FailureEndpoint{env: env, config: config}
}

// Call resolves the failure: it raises out (returns the stored error) when
// FailureRaiseOut is set, otherwise it redirects to the failure path.
func (f *FailureEndpoint) Call() (Response, error) {
	if f.config.FailureRaiseOut {
		if err, ok := f.env["omniauth.error"].(error); ok && err != nil {
			return Response{}, err
		}
		return Response{}, NewError(f.messageKey(), "OmniAuth failure")
	}
	return f.redirectToFailure(), nil
}

// messageKey returns the stored failure key, or "" if absent.
func (f *FailureEndpoint) messageKey() string {
	if k, ok := f.env["omniauth.error.type"].(string); ok {
		return k
	}
	return ""
}

// strategyName returns the failing strategy's name, or "" if absent.
func (f *FailureEndpoint) strategyName() string {
	if s, ok := f.env["omniauth.error.strategy"].(*Strategy); ok {
		return s.Name()
	}
	return ""
}

// redirectToFailure builds the 302 to the failure path, escaping the reflected
// message and strategy query values (Rack::Utils.escape in OmniAuth).
func (f *FailureEndpoint) redirectToFailure() Response {
	script, _ := f.env[rack.ScriptName].(string)
	path := script + f.config.PathPrefix + "/failure?message=" +
		rack.Escape(f.messageKey()) + "&strategy=" + rack.Escape(f.strategyName())
	return redirect(path)
}
