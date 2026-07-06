// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

// Error is the base OmniAuth error (OmniAuth::Error). It carries the failure
// message key that the failure flow reflects into
// `/auth/failure?message=<key>` — the machine-readable reason, distinct from the
// human message.
type Error struct {
	// MessageKey is the symbolic failure reason (e.g. "invalid_credentials").
	MessageKey string
	// Msg is the human-readable message.
	Msg string
	// Err is an optional wrapped cause.
	Err error
}

// NewError builds an [Error] with the given key and message.
func NewError(key, msg string) *Error {
	return &Error{MessageKey: key, Msg: msg}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return e.MessageKey
}

// Unwrap exposes the wrapped cause, if any.
func (e *Error) Unwrap() error { return e.Err }

// MessageKeyValue returns the failure message key. It is promoted to the
// specific error types below, so the engine can extract a key from any OmniAuth
// error uniformly.
func (e *Error) MessageKeyValue() string { return e.MessageKey }

// AuthenticityError is raised by the request-validation (CSRF) hook when the
// authenticity token is missing or wrong — OmniAuth::AuthenticityError. It maps
// to the "authenticity_error" failure key.
type AuthenticityError struct {
	Base *Error
}

// NewAuthenticityError builds an [AuthenticityError] with the given message.
func NewAuthenticityError(msg string) *AuthenticityError {
	if msg == "" {
		msg = "Forbidden"
	}
	return &AuthenticityError{Base: NewError("authenticity_error", msg)}
}

// Error implements the error interface.
func (e *AuthenticityError) Error() string { return e.Base.Error() }

// Unwrap exposes the base error.
func (e *AuthenticityError) Unwrap() error { return e.Base }

// MessageKeyValue returns the failure message key.
func (e *AuthenticityError) MessageKeyValue() string { return e.Base.MessageKey }

// NoSessionError is raised when a request reaches the middleware without a Rack
// session — OmniAuth::NoSessionError. Unlike a strategy failure it is not
// redirected; it propagates to the host, which must mount a session store ahead
// of OmniAuth.
type NoSessionError struct {
	Base *Error
}

// NewNoSessionError builds a [NoSessionError] with the given message.
func NewNoSessionError(msg string) *NoSessionError {
	return &NoSessionError{Base: NewError("no_session", msg)}
}

// Error implements the error interface.
func (e *NoSessionError) Error() string { return e.Base.Error() }

// Unwrap exposes the base error.
func (e *NoSessionError) Unwrap() error { return e.Base }

// MessageKeyValue returns the failure message key.
func (e *NoSessionError) MessageKeyValue() string { return e.Base.MessageKey }

// keyer is satisfied by any OmniAuth error that can name its failure key.
type keyer interface{ MessageKeyValue() string }

// messageKey extracts the failure key from err, falling back to fallback when
// err does not carry one.
func messageKey(err error, fallback string) string {
	if k, ok := err.(keyer); ok && k.MessageKeyValue() != "" {
		return k.MessageKeyValue()
	}
	return fallback
}
