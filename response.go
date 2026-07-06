// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

import "github.com/go-ruby-rack/rack"

// Response is a Rack response tuple `[status, headers, body]`, the value a Rack
// application (and thus each middleware phase) returns. Headers reuses
// rack.Headers so it composes with the rest of the go-ruby-* Rack stack.
type Response struct {
	Status  int
	Headers *rack.Headers
	Body    []string
}

// App is a Rack application: it receives an env and returns a response, or an
// error to propagate (a raised exception in Rack terms). Each [Strategy] is an
// App that wraps the downstream App.
type App interface {
	Call(env rack.Env) (Response, error)
}

// AppFunc adapts a function to the [App] interface.
type AppFunc func(env rack.Env) (Response, error)

// Call implements [App].
func (f AppFunc) Call(env rack.Env) (Response, error) { return f(env) }

// redirect builds a 302 response to location, mirroring OmniAuth's redirects
// (request-phase provider redirect, failure redirect, mock callback redirect).
func redirect(location string) Response {
	h := rack.NewHeaders()
	h.Set("Location", location)
	h.Set("Content-Type", "text/html")
	return Response{Status: 302, Headers: h, Body: []string{"302 Moved"}}
}
