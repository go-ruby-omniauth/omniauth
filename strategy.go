// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

import (
	"strings"

	"github.com/go-ruby-rack/rack"
)

// Phase names passed to a [StrategyPhase].
const (
	// PhaseRequest is the request phase: kick off authentication, typically by
	// redirecting the browser to the provider.
	PhaseRequest = "request"
	// PhaseCallback is the callback phase: the provider has returned, resolve the
	// authenticated identity into an [AuthHash].
	PhaseCallback = "callback"
)

// PhaseResult is what a [StrategyPhase] returns to the engine.
//
// For PhaseRequest, set Response to the provider redirect (or any short-circuit
// response). For PhaseCallback, set Auth to the resolved identity — the engine
// stores it at env["omniauth.auth"] and calls through to the app — or set
// Response to short-circuit. Either phase may instead set Fail (with an optional
// Err) to take the failure flow.
type PhaseResult struct {
	// Response short-circuits the phase with this response.
	Response *Response
	// Auth is the callback-phase resolved identity.
	Auth *AuthHash
	// Fail, when non-empty, is the failure message key to fail with.
	Fail string
	// Err is the error carried into the failure env alongside Fail.
	Err error
}

// StrategyPhase is the provider seam: the engine calls it with the provider
// name, the phase ("request" or "callback") and the Rack env (typed `any` so the
// seam is free of this package's Rack choice), and it returns a [PhaseResult].
// This is where provider-specific logic — OAuth redirects, token exchange,
// identity mapping — lives, outside this pure engine.
type StrategyPhase func(name, phase string, env any) PhaseResult

// Options are per-strategy settings, the analogue of a strategy's options block.
// A zero Options is fine; unset fields fall back to the engine [Config].
type Options struct {
	// PathPrefix overrides Config.PathPrefix for this strategy when non-empty.
	PathPrefix string
	// RequestPath overrides the derived request path when non-empty.
	RequestPath string
	// CallbackPath overrides the derived callback path when non-empty.
	CallbackPath string
	// Args carries arbitrary provider options (client id/secret, scope, …).
	Args map[string]any
}

// Strategy is one provider's middleware instance: it wraps the downstream [App],
// intercepts that provider's request and callback paths, and passes everything
// else through. It is OmniAuth::Strategy — the unit `Builder#provider` mounts.
type Strategy struct {
	name    string
	app     App
	options *Options
	phase   StrategyPhase
	config  *Config
}

// NewStrategy builds a Strategy for provider name that wraps app, running phase
// for its request/callback bodies under config. options may be nil.
func NewStrategy(name string, app App, phase StrategyPhase, config *Config, options *Options) *Strategy {
	return &Strategy{name: name, app: app, options: options, phase: phase, config: config}
}

// Name returns the provider name.
func (s *Strategy) Name() string { return s.name }

// Options returns the strategy options (never nil).
func (s *Strategy) Options() *Options {
	if s.options == nil {
		return &Options{}
	}
	return s.options
}

// Call is the middleware entry point (OmniAuth::Strategy#call!). It routes the
// request to the request or callback phase when the path and method match, runs
// the mock flow in test mode, and otherwise passes through to the wrapped app.
func (s *Strategy) Call(env rack.Env) (Response, error) {
	if s.config.RequireSession {
		if _, ok := env[rack.RackSession]; !ok {
			return Response{}, NewNoSessionError("You must provide a session to use OmniAuth.")
		}
	}
	req := rack.NewRequest(env)
	if s.onAuthPath(req) {
		env["omniauth.strategy"] = s
	}
	if s.config.TestMode {
		return s.mockCall(env, req)
	}
	if s.onAuthPath(req) && s.isOptionsRequest(req) {
		return s.optionsRequestCall(), nil
	}
	if s.onRequestPath(req) && s.methodAllowed(req) {
		return s.requestCall(env)
	}
	if s.onCallbackPath(req) {
		return s.callbackCall(env)
	}
	return s.app.Call(env)
}

// requestCall runs the request phase: the CSRF hook, then the provider redirect.
func (s *Strategy) requestCall(env rack.Env) (Response, error) {
	s.config.log("info", "Request phase initiated.")
	if s.config.BeforeRequestPhase != nil {
		s.config.BeforeRequestPhase(env)
	}
	if s.config.RequestValidationPhase != nil {
		if err := s.config.RequestValidationPhase(env); err != nil {
			return s.fail(env, messageKey(err, "authenticity_error"), err)
		}
	}
	res := s.phase(s.name, PhaseRequest, env)
	if res.Fail != "" {
		return s.fail(env, res.Fail, res.Err)
	}
	if res.Response == nil {
		return s.fail(env, "invalid_request", NewError("invalid_request", "request phase produced no response"))
	}
	return *res.Response, nil
}

// callbackCall runs the callback phase: restore origin/params from the session,
// then resolve the identity and hand off to the app.
func (s *Strategy) callbackCall(env rack.Env) (Response, error) {
	s.config.log("info", "Callback phase initiated.")
	s.restoreSession(env)
	if s.config.BeforeCallbackPhase != nil {
		s.config.BeforeCallbackPhase(env)
	}
	res := s.phase(s.name, PhaseCallback, env)
	if res.Fail != "" {
		return s.fail(env, res.Fail, res.Err)
	}
	if res.Response != nil {
		return *res.Response, nil
	}
	auth := res.Auth
	if auth == nil {
		auth = NewAuthHash()
	}
	auth.Set("provider", s.name)
	env["omniauth.auth"] = auth
	return s.app.Call(env)
}

// restoreSession moves the stored omniauth origin/params from the session into
// the env, matching callback_call's session hand-off.
func (s *Strategy) restoreSession(env rack.Env) {
	env["omniauth.params"] = map[string]any{}
	sess, ok := env[rack.RackSession].(map[string]any)
	if !ok {
		return
	}
	if o, ok := sess["omniauth.origin"]; ok {
		delete(sess, "omniauth.origin")
		if os, _ := o.(string); os != "" {
			env["omniauth.origin"] = os
		} else {
			env["omniauth.origin"] = nil
		}
	}
	if p, ok := sess["omniauth.params"]; ok {
		delete(sess, "omniauth.params")
		env["omniauth.params"] = p
	}
}

// fail! stores the failure context in the env and delegates to on_failure.
func (s *Strategy) fail(env rack.Env, key string, err error) (Response, error) {
	s.config.log("error", "Authentication failure! "+key)
	env["omniauth.error"] = err
	env["omniauth.error.type"] = key
	env["omniauth.error.strategy"] = s
	return s.config.OnFailure(env)
}

// optionsRequestCall answers a CORS-style OPTIONS probe on an auth path with the
// allowed verbs, matching options_request_call.
func (s *Strategy) optionsRequestCall() Response {
	h := rack.NewHeaders()
	h.Set("Allow", strings.Join(s.config.methods(), ", "))
	return Response{Status: 200, Headers: h, Body: []string{}}
}

// --- mock flow (test mode) -------------------------------------------------

// mockCall is the test-mode analogue of Call.
func (s *Strategy) mockCall(env rack.Env, req *rack.Request) (Response, error) {
	if s.onRequestPath(req) && s.methodAllowed(req) {
		return s.mockRequestCall(req), nil
	}
	if s.onCallbackPath(req) {
		return s.mockCallbackCall(env)
	}
	return s.app.Call(env)
}

// mockRequestCall redirects straight to the callback path, carrying the query.
func (s *Strategy) mockRequestCall(req *rack.Request) Response {
	target := s.callbackPathValue()
	if qs := req.QueryString(); qs != "" {
		target += "?" + qs
	}
	return redirect(target)
}

// mockCallbackCall serves the mocked identity, or takes the failure flow when
// the provider is configured to fail.
func (s *Strategy) mockCallbackCall(env rack.Env) (Response, error) {
	if key, ok := s.config.MockFailure[s.name]; ok {
		return s.fail(env, key, nil)
	}
	mock := s.config.MockAuth[s.name]
	if mock == nil {
		mock = s.config.MockAuth["default"]
	}
	if mock == nil {
		return s.fail(env, "invalid_credentials", nil)
	}
	mock.Set("provider", s.name)
	env["omniauth.auth"] = mock
	env["omniauth.params"] = map[string]any{}
	return s.app.Call(env)
}

// --- routing ---------------------------------------------------------------

// pathPrefix is the effective mount prefix for this strategy.
func (s *Strategy) pathPrefix() string {
	if s.options != nil && s.options.PathPrefix != "" {
		return s.options.PathPrefix
	}
	return s.config.PathPrefix
}

// requestPathValue is the effective request path.
func (s *Strategy) requestPathValue() string {
	if s.options != nil && s.options.RequestPath != "" {
		return s.options.RequestPath
	}
	return s.pathPrefix() + "/" + s.name
}

// callbackPathValue is the effective callback path.
func (s *Strategy) callbackPathValue() string {
	if s.options != nil && s.options.CallbackPath != "" {
		return s.options.CallbackPath
	}
	return s.pathPrefix() + "/" + s.name + "/callback"
}

// currentPath is request.path with a single trailing slash stripped, matching
// OmniAuth's current_path.
func currentPath(req *rack.Request) string {
	p := req.Path()
	if n := len(p); n > 0 && p[n-1] == '/' {
		p = p[:n-1]
	}
	return p
}

// onPath reports whether the current path case-insensitively equals path.
func onPath(req *rack.Request, path string) bool {
	return strings.EqualFold(currentPath(req), path)
}

func (s *Strategy) onRequestPath(req *rack.Request) bool  { return onPath(req, s.requestPathValue()) }
func (s *Strategy) onCallbackPath(req *rack.Request) bool { return onPath(req, s.callbackPathValue()) }
func (s *Strategy) onAuthPath(req *rack.Request) bool {
	return s.onRequestPath(req) || s.onCallbackPath(req)
}

// methodAllowed reports whether the request verb is permitted on the request path.
func (s *Strategy) methodAllowed(req *rack.Request) bool {
	m := strings.ToUpper(req.RequestMethod())
	for _, a := range s.config.methods() {
		if strings.ToUpper(a) == m {
			return true
		}
	}
	return false
}

// isOptionsRequest reports whether the request verb is OPTIONS.
func (s *Strategy) isOptionsRequest(req *rack.Request) bool {
	return strings.ToUpper(req.RequestMethod()) == rack.MethodOptions
}
