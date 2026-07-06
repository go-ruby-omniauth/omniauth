// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package omniauth is a pure-Go (no cgo) reimplementation of the engine of
// Ruby's OmniAuth — the Rack middleware and strategy framework that
// standardises multi-provider authentication — matching the observable
// behaviour of the `omniauth` gem (OmniAuth 2.x, MRI 4.0.5).
//
// It models the parts of OmniAuth that are interpreter-independent and provider
// -agnostic: the request/callback routing state-machine over the `/auth/:provider`
// and `/auth/:provider/callback` paths, the allowed-request-methods gate, the
// request-phase CSRF (AuthenticityTokenProtection) hook, the shape of the
// [AuthHash] (provider/uid/info/credentials/extra), and the failure flow that
// redirects to `/auth/failure?message=…&strategy=…`. The provider-specific
// bodies — what a request phase redirects to, what a callback phase resolves the
// identity to — and the HTTP session are host concerns, supplied through the
// [StrategyPhase] seam and the Rack env.
//
// The Rack environment, request and response types come from
// github.com/go-ruby-rack/rack, so this package composes with the rest of the
// go-ruby-* Rack stack without a second Rack model. The package is the OmniAuth
// backend for go-embedded-ruby, but is a standalone, reusable module with no
// dependency on the Ruby runtime — a sibling of go-ruby-rack and go-ruby-erb.
package omniauth
