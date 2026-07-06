// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

import (
	"fmt"

	"github.com/go-ruby-rack/rack"
)

// Strategies is the provider registry — the analogue of the OmniAuth::Strategies
// namespace. A provider registers its [StrategyPhase] under a name, and a
// [Builder] resolves each mounted provider through it. This decouples the set of
// available providers from the middleware stack.
type Strategies struct {
	order []string
	m     map[string]StrategyPhase
}

// NewStrategies returns an empty registry.
func NewStrategies() *Strategies {
	return &Strategies{m: map[string]StrategyPhase{}}
}

// Register adds (or replaces) the phase handler for a provider name and returns
// the registry for chaining.
func (r *Strategies) Register(name string, phase StrategyPhase) *Strategies {
	if _, ok := r.m[name]; !ok {
		r.order = append(r.order, name)
	}
	r.m[name] = phase
	return r
}

// Lookup returns the phase handler registered for name.
func (r *Strategies) Lookup(name string) (StrategyPhase, bool) {
	p, ok := r.m[name]
	return p, ok
}

// Names returns the registered provider names in registration order.
func (r *Strategies) Names() []string {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// providerReg is one mounted provider entry.
type providerReg struct {
	name    string
	options *Options
}

// Builder mounts providers as a stack of [Strategy] middlewares over an app,
// mirroring OmniAuth::Builder (a Rack::Builder that adds a `provider` DSL).
type Builder struct {
	config     *Config
	strategies *Strategies
	providers  []providerReg
}

// NewBuilder returns a Builder that resolves providers through strategies under
// config. Both must be non-nil.
func NewBuilder(config *Config, strategies *Strategies) *Builder {
	return &Builder{config: config, strategies: strategies}
}

// Provider mounts the named provider with the given options (nil is fine) and
// returns the Builder for chaining — the analogue of `provider :name, …`.
func (b *Builder) Provider(name string, options *Options) *Builder {
	b.providers = append(b.providers, providerReg{name: name, options: options})
	return b
}

// Build wraps app with the mounted providers, outermost first (the first
// provider mounted sees the request first, as with Rack `use` ordering). It
// fails if a mounted provider was never registered in the [Strategies].
func (b *Builder) Build(app App) (App, error) {
	result := app
	for i := len(b.providers) - 1; i >= 0; i-- {
		p := b.providers[i]
		phase, ok := b.strategies.Lookup(p.name)
		if !ok {
			return nil, fmt.Errorf("omniauth: provider %q is not registered", p.name)
		}
		result = NewStrategy(p.name, result, phase, b.config, p.options)
	}
	return result, nil
}

// passThroughApp is the terminal Rack app when a builder has no downstream app:
// it 404s, so an auth path that no strategy claimed is visibly unhandled.
type passThroughApp struct{}

// Call implements [App].
func (passThroughApp) Call(env rack.Env) (Response, error) {
	h := rack.NewHeaders()
	h.Set("Content-Type", "text/plain")
	return Response{Status: 404, Headers: h, Body: []string{"Not Found"}}, nil
}

// PassThroughApp returns a terminal 404 app, handy as the base of a Build when
// the middleware stack is meant to fully own the request.
func PassThroughApp() App { return passThroughApp{} }
