// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

import "github.com/go-ruby-rack/rack"

// Config holds the engine-wide settings, the analogue of OmniAuth.config. The
// zero value is not usable; build one with [DefaultConfig] and adjust.
type Config struct {
	// PathPrefix is the mount point for the auth routes (default "/auth"), so the
	// request path is "<PathPrefix>/<provider>" and the callback is
	// "<PathPrefix>/<provider>/callback".
	PathPrefix string

	// AllowedRequestMethods lists the upper-case HTTP verbs permitted on the
	// request path. Empty means the OmniAuth 2.x default, POST only.
	AllowedRequestMethods []string

	// RequireSession makes the middleware raise a [NoSessionError] when a request
	// arrives without a Rack session (env["rack.session"]). Default true.
	RequireSession bool

	// TestMode short-circuits the strategies to the mock flow: the request phase
	// redirects straight to the callback and the callback phase serves a mocked
	// auth hash from MockAuth / MockFailure instead of talking to a provider.
	TestMode bool

	// MockAuth maps a provider name (or "default") to the auth hash its mocked
	// callback yields in TestMode.
	MockAuth map[string]*AuthHash

	// MockFailure maps a provider name to a failure key; a mocked callback for
	// such a provider takes the failure flow in TestMode.
	MockFailure map[string]string

	// FailureRaiseOut makes the default failure endpoint propagate the error
	// instead of redirecting — OmniAuth's raise_out! for dev/test environments.
	FailureRaiseOut bool

	// RequestValidationPhase is the request-phase CSRF hook
	// (OmniAuth's request_validation_phase / AuthenticityTokenProtection). A
	// non-nil error it returns takes the failure flow. nil disables the check.
	RequestValidationPhase func(env any) error

	// BeforeRequestPhase and BeforeCallbackPhase run just before the respective
	// phase, mirroring OmniAuth.config.before_request_phase / before_callback_phase.
	BeforeRequestPhase  func(env any)
	BeforeCallbackPhase func(env any)

	// OnFailure resolves a failure into a response. fail! sets
	// env["omniauth.error"], ["omniauth.error.type"] and ["omniauth.error.strategy"]
	// before calling it. Default is the [FailureEndpoint] redirect.
	OnFailure func(env rack.Env) (Response, error)

	// Logger receives (level, message) log lines; nil discards them.
	Logger func(level, message string)
}

// DefaultConfig returns a Config with OmniAuth 2.x defaults: "/auth" prefix,
// POST-only request methods, session required, the failure redirect wired up.
func DefaultConfig() *Config {
	c := &Config{
		PathPrefix:     "/auth",
		RequireSession: true,
		MockAuth:       map[string]*AuthHash{},
		MockFailure:    map[string]string{},
	}
	c.OnFailure = func(env rack.Env) (Response, error) {
		return NewFailureEndpoint(env, c).Call()
	}
	return c
}

// methods returns the effective allowed request verbs (default POST).
func (c *Config) methods() []string {
	if len(c.AllowedRequestMethods) > 0 {
		return c.AllowedRequestMethods
	}
	return []string{rack.MethodPost}
}

// log emits a line through the configured Logger, if any.
func (c *Config) log(level, message string) {
	if c.Logger != nil {
		c.Logger(level, message)
	}
}

// AuthenticityTokenProtection builds a request_validation_phase hook that fails
// with an [AuthenticityError] unless valid reports the request's CSRF token
// good. The token check itself (session vs request param) is the host's, kept
// out of this pure-Go core; this wires the raise/allow decision faithfully.
func AuthenticityTokenProtection(valid func(env any) bool) func(env any) error {
	return func(env any) error {
		if valid(env) {
			return nil
		}
		return NewAuthenticityError("")
	}
}
