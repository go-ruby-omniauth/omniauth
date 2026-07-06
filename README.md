<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-omniauth/brand/main/social/go-ruby-omniauth-omniauth.png" alt="go-ruby-omniauth/omniauth" width="720"></p>

# omniauth — go-ruby-omniauth

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-omniauth.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of the engine of Ruby's
[OmniAuth](https://github.com/omniauth/omniauth)** — the Rack middleware and
strategy framework that standardises multi-provider authentication — matching the
observable behaviour of the `omniauth` gem (**OmniAuth 2.x**, MRI 4.0.5). It owns
the request/callback routing state-machine over `/auth/:provider` and
`/auth/:provider/callback`, the allowed-request-methods gate, the request-phase
CSRF hook, the `AuthHash` shape and the failure-redirect flow — **without any Ruby
runtime**.

It is the OmniAuth backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-rack](https://github.com/go-ruby-rack/rack) (whose Rack `Env`,
`Request`, `Response` and `Headers` it reuses) and
[go-ruby-erb](https://github.com/go-ruby-erb/erb).

> **The engine, not the providers.** OmniAuth's value is the *framework*: routing,
> phases, the auth-hash contract, failure handling. That is exactly what this
> package models. The provider-specific bodies (what a request phase redirects to,
> how a callback resolves an identity) and the HTTP session are **seams** — the
> host supplies them, so the core stays pure and dependency-light. A later
> [go-embedded-ruby](https://github.com/go-embedded-ruby/ruby) binding plugs the
> Ruby strategy objects into these seams.

## The StrategyPhase seam

Every provider difference funnels through one function:

```go
type StrategyPhase func(name, phase string, env any) PhaseResult
```

The engine calls it with the provider `name`, the `phase`
(`omniauth.PhaseRequest` = `"request"` or `omniauth.PhaseCallback` =
`"callback"`) and the Rack `env`. For the **request** phase it returns a
`PhaseResult{Response: …}` — typically a 302 to the provider. For the **callback**
phase it returns a `PhaseResult{Auth: …}` — the resolved [AuthHash], which the
engine stores at `env["omniauth.auth"]` before calling through to the app. Either
phase may instead return `PhaseResult{Fail: "reason", Err: …}` to enter the
failure flow. The provider logic itself (OAuth handshakes, token exchange) lives
in the seam, outside this package.

## Install

```sh
go get github.com/go-ruby-omniauth/omniauth
```

## Usage

```go
package main

import (
	"github.com/go-ruby-omniauth/omniauth"
	"github.com/go-ruby-rack/rack"
)

func main() {
	cfg := omniauth.DefaultConfig() // "/auth" prefix, POST-only, session required

	// Register providers. A real provider does an OAuth redirect / token
	// exchange here; this fake one shows the two phases.
	strategies := omniauth.NewStrategies()
	strategies.Register("developer", func(name, phase string, env any) omniauth.PhaseResult {
		if phase == omniauth.PhaseRequest {
			r := omniauth.Response{ /* 302 to the provider */ }
			return omniauth.PhaseResult{Response: &r}
		}
		// callback: resolve the identity
		auth := omniauth.NewAuthHash().SetUID("12345")
		auth.Info().Set("email", "ada@example.com")
		return omniauth.PhaseResult{Auth: auth}
	})

	// The app that runs once authentication succeeds.
	app := omniauth.AppFunc(func(env rack.Env) (omniauth.Response, error) {
		_ = env["omniauth.auth"].(*omniauth.AuthHash) // provider, uid, info, …
		return omniauth.Response{Status: 200, Headers: rack.NewHeaders(), Body: []string{"signed in"}}, nil
	})

	// Mount the providers as middleware over the app.
	handler, _ := omniauth.NewBuilder(cfg, strategies).
		Provider("developer", nil).
		Build(app)

	_ = handler // handler.Call(env) drives /auth/developer and /auth/developer/callback
}
```

## API

```go
// engine configuration
func DefaultConfig() *Config
type Config struct { PathPrefix; AllowedRequestMethods; RequireSession; TestMode;
                     MockAuth; MockFailure; FailureRaiseOut; RequestValidationPhase;
                     BeforeRequestPhase; BeforeCallbackPhase; OnFailure; Logger }
func AuthenticityTokenProtection(valid func(env any) bool) func(env any) error

// provider registry + middleware stack
type Strategies struct{ … }
func NewStrategies() *Strategies
func (r *Strategies) Register(name string, phase StrategyPhase) *Strategies
func (r *Strategies) Lookup(name string) (StrategyPhase, bool)
func (r *Strategies) Names() []string

type Builder struct{ … }
func NewBuilder(config *Config, strategies *Strategies) *Builder
func (b *Builder) Provider(name string, options *Options) *Builder
func (b *Builder) Build(app App) (App, error)
func PassThroughApp() App

// the middleware / phase state-machine
type Strategy struct{ … }
func NewStrategy(name string, app App, phase StrategyPhase, config *Config, options *Options) *Strategy
func (s *Strategy) Call(env rack.Env) (Response, error) // OmniAuth::Strategy#call!
func (s *Strategy) Name() string
func (s *Strategy) Options() *Options

// the provider seam
type StrategyPhase func(name, phase string, env any) PhaseResult
type PhaseResult struct { Response *Response; Auth *AuthHash; Fail string; Err error }
const PhaseRequest, PhaseCallback = "request", "callback"

// the auth hash (OmniAuth::AuthHash)
type AuthHash struct{ … }
func NewAuthHash() *AuthHash
func AuthHashOf(pairs ...any) *AuthHash
func (h *AuthHash) Set(key string, val any) *AuthHash
func (h *AuthHash) Get / GetOK / Has / Delete / Keys / Len / GetString
func (h *AuthHash) Provider() string
func (h *AuthHash) UID() string
func (h *AuthHash) SetUID(uid string) *AuthHash
func (h *AuthHash) ValidQ() bool                 // valid? (provider && uid)
func (h *AuthHash) Info() *InfoHash              // info sub-hash
func (h *AuthHash) Credentials() *AuthHash
func (h *AuthHash) Extra() *AuthHash
type InfoHash struct{ *AuthHash }
func (i *InfoHash) Name() string                 // name || "first last" || nickname || email

// responses, errors, failure
type Response struct { Status int; Headers *rack.Headers; Body []string }
type App interface{ Call(env rack.Env) (Response, error) }
type AppFunc func(env rack.Env) (Response, error)
type Error struct { MessageKey, Msg string; Err error }
type AuthenticityError struct{ … }               // request-phase CSRF failure
type NoSessionError struct{ … }                  // no rack.session
type FailureEndpoint struct{ … }                 // default on_failure
```

## Fidelity vs the `omniauth` gem (2.x)

| OmniAuth (Ruby)                              | This package |
|----------------------------------------------|--------------|
| `OmniAuth::Builder` / `provider :name`        | `Builder` + `Strategies.Register` / `Builder.Provider` |
| `OmniAuth::Strategy#call!` routing            | `Strategy.Call` — request / callback / options / pass-through |
| `path_prefix`, `request_path`, `callback_path` | `Config.PathPrefix`, `Options.RequestPath` / `CallbackPath` |
| `allowed_request_methods` (default `[:post]`) | `Config.AllowedRequestMethods` (default `POST`) |
| `request_validation_phase` (AuthenticityToken) | `Config.RequestValidationPhase` + `AuthenticityTokenProtection` |
| `request_phase` → provider redirect           | `StrategyPhase(PhaseRequest)` → `PhaseResult.Response` |
| `callback_phase` → `env["omniauth.auth"]`     | `StrategyPhase(PhaseCallback)` → `PhaseResult.Auth` |
| `OmniAuth::AuthHash` (info/credentials/extra) | `AuthHash` + `InfoHash` (indifferent-access, `#name` derivation) |
| `fail!` → `on_failure` → `/auth/failure?…`    | `Strategy.fail` → `Config.OnFailure` → `FailureEndpoint` |
| `OmniAuth::Error` / `AuthenticityError` / `NoSessionError` | same three types |
| test mode + `mock_auth`                        | `Config.TestMode` + `MockAuth` / `MockFailure` |

**Out of scope (host/seam concerns):** the socket accept loop and Rack handler
(go-ruby-rack's `doc.go` notes these belong to the host), the HTTP session store,
the concrete provider strategies (OAuth1/OAuth2/OpenID handshakes), and CSRF token
storage — the `RequestValidationPhase` wires the raise/allow decision, the host
supplies the token check. The Rack `Env`/`Request`/`Response`/`Headers` are reused
directly from [go-ruby-rack](https://github.com/go-ruby-rack/rack).

## Tests & coverage

The suite is deterministic and Ruby-free: the engine — request/callback routing,
the allowed-methods gate, the CSRF hook, the success auth-hash, the failure
redirect and the test-mode mock provider — is exercised through fake strategy and
env seams. Those tests alone hold coverage at **100%**, so the qemu cross-arch and
Windows lanes pass the gate.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

CGO-free, `gofmt` + `go vet` clean, and green across the six 64-bit Go targets
(amd64, arm64, riscv64, loong64, ppc64le, s390x — including big-endian s390x) and
three OSes (Linux, macOS, Windows).

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-omniauth/omniauth authors.

## WebAssembly

Being pure Go (CGO=0), this library also compiles to **WebAssembly** — both
`GOOS=js GOARCH=wasm` (browser / Node.js) and `GOOS=wasip1 GOARCH=wasm` (WASI).
CI builds both targets on every push, alongside the six 64-bit native/qemu arches.

```sh
GOOS=js     GOARCH=wasm go build ./...   # browser / Node
GOOS=wasip1 GOARCH=wasm go build ./...   # WASI (wasmtime, wasmer, wasmedge, …)
```
