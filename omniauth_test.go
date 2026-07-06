// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ruby-rack/rack"
)

// --- helpers ---------------------------------------------------------------

// recordApp records the last env it was called with and returns a 200.
type recordApp struct {
	called bool
	env    rack.Env
}

func (a *recordApp) Call(env rack.Env) (Response, error) {
	a.called = true
	a.env = env
	h := rack.NewHeaders()
	h.Set("Content-Type", "text/plain")
	return Response{Status: 200, Headers: h, Body: []string{"app"}}, nil
}

func baseEnv(method, path string) rack.Env {
	return rack.Env{
		rack.RequestMethod: method,
		rack.PathInfo:      path,
		rack.ScriptName:    "",
		rack.RackSession:   map[string]any{},
	}
}

func header(r Response, key string) string {
	if r.Headers == nil {
		return ""
	}
	if v, ok := r.Headers.Get(key).(string); ok {
		return v
	}
	return ""
}

// --- AuthHash --------------------------------------------------------------

func TestAuthHashBasics(t *testing.T) {
	h := NewAuthHash()
	h.Set("uid", "123").Set("provider", "dev")
	h.Set("uid", "456") // update existing, keeps one key
	if got := h.UID(); got != "456" {
		t.Fatalf("uid = %q", got)
	}
	if h.Provider() != "dev" {
		t.Fatalf("provider = %q", h.Provider())
	}
	if h.Len() != 2 {
		t.Fatalf("len = %d", h.Len())
	}
	if keys := h.Keys(); len(keys) != 2 || keys[0] != "uid" {
		t.Fatalf("keys = %v", keys)
	}
	if v, ok := h.GetOK("uid"); !ok || v != "456" {
		t.Fatalf("GetOK = %v %v", v, ok)
	}
	if _, ok := h.GetOK("nope"); ok {
		t.Fatal("GetOK absent should be false")
	}
	if !h.Has("provider") || h.Has("nope") {
		t.Fatal("Has")
	}
	if h.Get("provider") != "dev" {
		t.Fatal("Get")
	}
	if h.GetString("provider") != "dev" || h.GetString("nope") != "" {
		t.Fatal("GetString")
	}
	h.Set("n", 7)
	if h.GetString("n") != "" {
		t.Fatal("GetString non-string")
	}
	h.SetUID("z")
	if h.UID() != "z" {
		t.Fatal("SetUID")
	}
}

func TestAuthHashOf(t *testing.T) {
	h := AuthHashOf("uid", "1", 99, "ignored-key", "trailing")
	if h.UID() != "1" {
		t.Fatalf("uid = %q", h.UID())
	}
	// the non-string key collapses to "" and the odd trailing element is dropped
	if !h.Has("") {
		t.Fatal("expected empty-string key from non-string pair")
	}
}

func TestAuthHashDelete(t *testing.T) {
	h := AuthHashOf("a", 1, "b", 2, "c", 3)
	if v, ok := h.Delete("b"); !ok || v != 2 {
		t.Fatalf("delete b = %v %v", v, ok)
	}
	if _, ok := h.Delete("b"); ok {
		t.Fatal("second delete should be false")
	}
	if keys := h.Keys(); len(keys) != 2 || keys[0] != "a" || keys[1] != "c" {
		t.Fatalf("keys after delete = %v", keys)
	}
}

func TestAuthHashValidQ(t *testing.T) {
	if NewAuthHash().ValidQ() {
		t.Fatal("empty should be invalid")
	}
	if AuthHashOf("provider", "dev").ValidQ() {
		t.Fatal("no uid should be invalid")
	}
	if AuthHashOf("uid", "1").ValidQ() {
		t.Fatal("no provider should be invalid")
	}
	if !AuthHashOf("provider", "dev", "uid", "1").ValidQ() {
		t.Fatal("both present should be valid")
	}
}

func TestAuthHashSubHashes(t *testing.T) {
	h := NewAuthHash()
	info := h.Info()
	info.Set("email", "a@b.c")
	if h.Info() != info { // second access returns the same InfoHash
		t.Fatal("Info not memoised")
	}
	h.Credentials().Set("token", "t")
	if h.Credentials().GetString("token") != "t" {
		t.Fatal("Credentials")
	}
	h.Extra().Set("raw", "x")
	if h.Extra().GetString("raw") != "x" {
		t.Fatal("Extra")
	}
}

func TestAuthHashInfoAdoptsPlainSub(t *testing.T) {
	h := NewAuthHash()
	plain := AuthHashOf("email", "a@b.c")
	h.Set("info", plain) // a plain *AuthHash, not an *InfoHash
	info := h.Info()     // adopts the plain sub-hash
	if info.GetString("email") != "a@b.c" {
		t.Fatalf("adopt failed: %q", info.GetString("email"))
	}
}

func TestAuthHashSubHashAdoptsExisting(t *testing.T) {
	h := NewAuthHash()
	plain := AuthHashOf("token", "t")
	h.Set("credentials", plain)
	if h.Credentials() != plain {
		t.Fatal("subHash should return existing *AuthHash")
	}
}

func TestInfoHashName(t *testing.T) {
	if NewInfoHash().Name() != "" {
		t.Fatal("empty name")
	}
	if got := (&InfoHash{AuthHash: AuthHashOf("email", "e@x")}).Name(); got != "e@x" {
		t.Fatalf("email fallback = %q", got)
	}
	if got := (&InfoHash{AuthHash: AuthHashOf("nickname", "nick", "email", "e@x")}).Name(); got != "nick" {
		t.Fatalf("nickname fallback = %q", got)
	}
	first := &InfoHash{AuthHash: AuthHashOf("first_name", "Ada")}
	if got := first.Name(); got != "Ada" {
		t.Fatalf("first only = %q", got)
	}
	last := &InfoHash{AuthHash: AuthHashOf("last_name", "Lovelace")}
	if got := last.Name(); got != "Lovelace" {
		t.Fatalf("last only = %q", got)
	}
	both := &InfoHash{AuthHash: AuthHashOf("first_name", "Ada", "last_name", "Lovelace")}
	if got := both.Name(); got != "Ada Lovelace" {
		t.Fatalf("both = %q", got)
	}
	explicit := &InfoHash{AuthHash: AuthHashOf("name", "Grace", "first_name", "X")}
	if got := explicit.Name(); got != "Grace" {
		t.Fatalf("explicit = %q", got)
	}
}

func TestNewInfoHashCarriesAuthHash(t *testing.T) {
	ih := NewInfoHash()
	ih.Set("k", "v")
	if ih.GetString("k") != "v" {
		t.Fatal("NewInfoHash")
	}
}

// --- errors ----------------------------------------------------------------

func TestErrors(t *testing.T) {
	e := NewError("k", "boom")
	if e.Error() != "boom" || e.MessageKeyValue() != "k" || e.Unwrap() != nil {
		t.Fatal("Error basics")
	}
	cause := errors.New("cause")
	e2 := &Error{MessageKey: "onlykey", Err: cause}
	if e2.Error() != "onlykey" { // Msg empty -> falls back to key
		t.Fatalf("key fallback = %q", e2.Error())
	}
	if e2.Unwrap() != cause {
		t.Fatal("Unwrap")
	}

	ae := NewAuthenticityError("")
	if ae.Error() != "Forbidden" || ae.MessageKeyValue() != "authenticity_error" || ae.Unwrap() == nil {
		t.Fatal("AuthenticityError")
	}
	if NewAuthenticityError("nope").Error() != "nope" {
		t.Fatal("AuthenticityError msg")
	}

	ns := NewNoSessionError("no sess")
	if ns.Error() != "no sess" || ns.MessageKeyValue() != "no_session" || ns.Unwrap() == nil {
		t.Fatal("NoSessionError")
	}
}

func TestMessageKey(t *testing.T) {
	if got := messageKey(NewError("k", "m"), "fb"); got != "k" {
		t.Fatalf("keyer = %q", got)
	}
	if got := messageKey(errors.New("plain"), "fb"); got != "fb" {
		t.Fatalf("plain = %q", got)
	}
	if got := messageKey(NewError("", "m"), "fb"); got != "fb" {
		t.Fatalf("empty-key keyer = %q", got)
	}
}

// --- config ----------------------------------------------------------------

func TestConfigDefaults(t *testing.T) {
	c := DefaultConfig()
	if c.PathPrefix != "/auth" || !c.RequireSession {
		t.Fatal("defaults")
	}
	if got := c.methods(); len(got) != 1 || got[0] != "POST" {
		t.Fatalf("default methods = %v", got)
	}
	c.AllowedRequestMethods = []string{"GET", "POST"}
	if got := c.methods(); len(got) != 2 {
		t.Fatalf("custom methods = %v", got)
	}
	c.log("info", "no logger") // nil logger branch: must not panic
	var seen string
	c.Logger = func(level, msg string) { seen = level + ":" + msg }
	c.log("warn", "hi")
	if seen != "warn:hi" {
		t.Fatalf("logger = %q", seen)
	}
}

func TestAuthenticityTokenProtection(t *testing.T) {
	ok := AuthenticityTokenProtection(func(env any) bool { return true })
	if err := ok(rack.Env{}); err != nil {
		t.Fatalf("valid = %v", err)
	}
	bad := AuthenticityTokenProtection(func(env any) bool { return false })
	if err := bad(rack.Env{}); err == nil {
		t.Fatal("invalid should error")
	}
}

// --- response --------------------------------------------------------------

func TestAppFunc(t *testing.T) {
	var f AppFunc = func(env rack.Env) (Response, error) {
		return Response{Status: 201}, nil
	}
	r, err := f.Call(rack.Env{})
	if err != nil || r.Status != 201 {
		t.Fatalf("AppFunc = %v %v", r, err)
	}
}

// --- failure ---------------------------------------------------------------

func TestFailureEndpointRedirect(t *testing.T) {
	c := DefaultConfig()
	s := NewStrategy("dev with space", &recordApp{}, nil, c, nil)
	env := rack.Env{
		rack.ScriptName:           "/app",
		"omniauth.error.type":     "invalid_credentials",
		"omniauth.error.strategy": s,
	}
	r, err := NewFailureEndpoint(env, c).Call()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	loc := header(r, "location")
	if !strings.HasPrefix(loc, "/app/auth/failure?message=invalid_credentials&strategy=") {
		t.Fatalf("loc = %q", loc)
	}
	if !strings.Contains(loc, "dev+with+space") && !strings.Contains(loc, "dev%20with%20space") {
		t.Fatalf("strategy not escaped: %q", loc)
	}
}

func TestFailureEndpointMissingContext(t *testing.T) {
	c := DefaultConfig()
	// no script name, no error.type, no strategy
	r, err := NewFailureEndpoint(rack.Env{}, c).Call()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := header(r, "location"); got != "/auth/failure?message=&strategy=" {
		t.Fatalf("loc = %q", got)
	}
}

func TestFailureEndpointRaiseOut(t *testing.T) {
	c := DefaultConfig()
	c.FailureRaiseOut = true
	boom := NewError("invalid_credentials", "boom")
	env := rack.Env{"omniauth.error": boom, "omniauth.error.type": "invalid_credentials"}
	if _, err := NewFailureEndpoint(env, c).Call(); err != boom {
		t.Fatalf("raise_out err = %v", err)
	}
	// raise-out with no stored error yields a synthesised one
	env2 := rack.Env{"omniauth.error.type": "invalid_credentials"}
	_, err := NewFailureEndpoint(env2, c).Call()
	if err == nil || err.Error() != "OmniAuth failure" {
		t.Fatalf("synthesised err = %v", err)
	}
}

// --- Strategies / Builder --------------------------------------------------

func TestStrategiesRegistry(t *testing.T) {
	r := NewStrategies()
	ph := func(name, phase string, env any) PhaseResult { return PhaseResult{} }
	r.Register("dev", ph).Register("dev", ph) // register + replace, one name
	r.Register("github", ph)
	if _, ok := r.Lookup("dev"); !ok {
		t.Fatal("lookup dev")
	}
	if _, ok := r.Lookup("nope"); ok {
		t.Fatal("lookup nope")
	}
	if names := r.Names(); len(names) != 2 || names[0] != "dev" || names[1] != "github" {
		t.Fatalf("names = %v", names)
	}
}

func TestBuilderBuildAndOrder(t *testing.T) {
	c := DefaultConfig()
	reg := NewStrategies()
	reg.Register("a", func(name, phase string, env any) PhaseResult { return PhaseResult{} })
	reg.Register("b", func(name, phase string, env any) PhaseResult { return PhaseResult{} })
	app := &recordApp{}
	built, err := NewBuilder(c, reg).Provider("a", nil).Provider("b", &Options{}).Build(app)
	if err != nil {
		t.Fatalf("build err = %v", err)
	}
	// outermost is provider "a"
	outer, ok := built.(*Strategy)
	if !ok || outer.Name() != "a" {
		t.Fatalf("outer = %#v", built)
	}
}

func TestBuilderUnregistered(t *testing.T) {
	built, err := NewBuilder(DefaultConfig(), NewStrategies()).Provider("ghost", nil).Build(&recordApp{})
	if err == nil || built != nil {
		t.Fatalf("expected error, got %v %v", built, err)
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("err = %v", err)
	}
}

func TestPassThroughApp(t *testing.T) {
	r, err := PassThroughApp().Call(rack.Env{})
	if err != nil || r.Status != 404 {
		t.Fatalf("passthrough = %v %v", r, err)
	}
}

// --- Strategy: routing & session -------------------------------------------

func okRequestPhase(redirectTo string) StrategyPhase {
	return func(name, phase string, env any) PhaseResult {
		if phase == PhaseRequest {
			r := redirect(redirectTo)
			return PhaseResult{Response: &r}
		}
		return PhaseResult{Auth: AuthHashOf("uid", "u1").SetUID("u1")}
	}
}

func TestStrategyNameAndOptions(t *testing.T) {
	s := NewStrategy("dev", &recordApp{}, nil, DefaultConfig(), nil)
	if s.Name() != "dev" {
		t.Fatal("name")
	}
	if s.Options() == nil {
		t.Fatal("nil options -> empty")
	}
	s2 := NewStrategy("dev", &recordApp{}, nil, DefaultConfig(), &Options{PathPrefix: "/x"})
	if s2.Options().PathPrefix != "/x" {
		t.Fatal("options passthrough")
	}
}

func TestStrategyNoSession(t *testing.T) {
	c := DefaultConfig()
	s := NewStrategy("dev", &recordApp{}, okRequestPhase("/p"), c, nil)
	env := rack.Env{rack.RequestMethod: "POST", rack.PathInfo: "/auth/dev"}
	_, err := s.Call(env)
	if _, ok := err.(*NoSessionError); !ok {
		t.Fatalf("expected NoSessionError, got %v", err)
	}
	// RequireSession off: no session is fine, passthrough for non-auth path
	c.RequireSession = false
	app := &recordApp{}
	s2 := NewStrategy("dev", app, okRequestPhase("/p"), c, nil)
	if _, err := s2.Call(rack.Env{rack.RequestMethod: "GET", rack.PathInfo: "/other"}); err != nil {
		t.Fatalf("passthrough err = %v", err)
	}
	if !app.called {
		t.Fatal("app should be called for non-auth path")
	}
}

func TestStrategyPassthroughNonAuth(t *testing.T) {
	app := &recordApp{}
	s := NewStrategy("dev", app, okRequestPhase("/p"), DefaultConfig(), nil)
	r, err := s.Call(baseEnv("GET", "/something"))
	if err != nil || r.Status != 200 || !app.called {
		t.Fatalf("passthrough = %v %v", r, err)
	}
}

func TestStrategyRequestPhaseRedirect(t *testing.T) {
	app := &recordApp{}
	s := NewStrategy("dev", app, okRequestPhase("https://provider/oauth"), DefaultConfig(), nil)
	r, err := s.Call(baseEnv("POST", "/auth/dev"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if r.Status != 302 || header(r, "location") != "https://provider/oauth" {
		t.Fatalf("redirect = %v", r)
	}
	if app.called {
		t.Fatal("app must not be called on request phase")
	}
}

func TestStrategyRequestMethodGate(t *testing.T) {
	// default POST-only: a GET on the request path is not intercepted -> passthrough
	app := &recordApp{}
	s := NewStrategy("dev", app, okRequestPhase("/p"), DefaultConfig(), nil)
	r, err := s.Call(baseEnv("GET", "/auth/dev"))
	if err != nil || !app.called || r.Status != 200 {
		t.Fatalf("GET on request path should pass through: %v %v", r, err)
	}
}

func TestStrategyBeforeRequestPhaseAndValidation(t *testing.T) {
	c := DefaultConfig()
	beforeRan := false
	c.BeforeRequestPhase = func(env any) { beforeRan = true }
	c.RequestValidationPhase = func(env any) error { return nil }
	s := NewStrategy("dev", &recordApp{}, okRequestPhase("/p"), c, nil)
	if _, err := s.Call(baseEnv("POST", "/auth/dev")); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !beforeRan {
		t.Fatal("BeforeRequestPhase not run")
	}
}

func TestStrategyCSRFFailAuthenticity(t *testing.T) {
	c := DefaultConfig()
	c.RequestValidationPhase = AuthenticityTokenProtection(func(env any) bool { return false })
	s := NewStrategy("dev", &recordApp{}, okRequestPhase("/p"), c, nil)
	r, err := s.Call(baseEnv("POST", "/auth/dev"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(header(r, "location"), "message=authenticity_error") {
		t.Fatalf("expected authenticity failure, got %q", header(r, "location"))
	}
}

func TestStrategyCSRFFailPlainError(t *testing.T) {
	c := DefaultConfig()
	c.RequestValidationPhase = func(env any) error { return errors.New("nope") }
	s := NewStrategy("dev", &recordApp{}, okRequestPhase("/p"), c, nil)
	r, err := s.Call(baseEnv("POST", "/auth/dev"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(header(r, "location"), "message=authenticity_error") {
		t.Fatalf("plain-error CSRF should map to authenticity_error, got %q", header(r, "location"))
	}
}

func TestStrategyRequestPhaseFailAndNoResponse(t *testing.T) {
	c := DefaultConfig()
	// phase returns an explicit Fail
	failPhase := func(name, phase string, env any) PhaseResult {
		return PhaseResult{Fail: "custom_failure", Err: NewError("custom_failure", "x")}
	}
	s := NewStrategy("dev", &recordApp{}, failPhase, c, nil)
	r, _ := s.Call(baseEnv("POST", "/auth/dev"))
	if !strings.Contains(header(r, "location"), "message=custom_failure") {
		t.Fatalf("fail = %q", header(r, "location"))
	}
	// phase returns neither Response nor Fail -> invalid_request failure
	emptyPhase := func(name, phase string, env any) PhaseResult { return PhaseResult{} }
	s2 := NewStrategy("dev", &recordApp{}, emptyPhase, c, nil)
	r2, _ := s2.Call(baseEnv("POST", "/auth/dev"))
	if !strings.Contains(header(r2, "location"), "message=invalid_request") {
		t.Fatalf("no-response = %q", header(r2, "location"))
	}
}

// --- Strategy: callback phase ----------------------------------------------

func TestStrategyCallbackSuccess(t *testing.T) {
	c := DefaultConfig()
	beforeRan := false
	c.BeforeCallbackPhase = func(env any) { beforeRan = true }
	app := &recordApp{}
	s := NewStrategy("dev", app, okRequestPhase("/p"), c, nil)
	env := baseEnv("GET", "/auth/dev/callback")
	sess := env[rack.RackSession].(map[string]any)
	sess["omniauth.origin"] = "/dashboard"
	sess["omniauth.params"] = map[string]any{"state": "abc"}
	r, err := s.Call(env)
	if err != nil || r.Status != 200 || !app.called {
		t.Fatalf("callback = %v %v called=%v", r, err, app.called)
	}
	if !beforeRan {
		t.Fatal("BeforeCallbackPhase not run")
	}
	auth, ok := app.env["omniauth.auth"].(*AuthHash)
	if !ok || auth.Provider() != "dev" || auth.UID() != "u1" {
		t.Fatalf("auth = %#v", app.env["omniauth.auth"])
	}
	if app.env["omniauth.origin"] != "/dashboard" {
		t.Fatalf("origin = %v", app.env["omniauth.origin"])
	}
	if _, ok := sess["omniauth.origin"]; ok {
		t.Fatal("origin should be consumed from session")
	}
}

func TestStrategyCallbackNilAuthAndEmptyOrigin(t *testing.T) {
	c := DefaultConfig()
	// phase returns no Auth -> engine builds an empty AuthHash with provider set
	phase := func(name, phase string, env any) PhaseResult { return PhaseResult{} }
	app := &recordApp{}
	s := NewStrategy("dev", app, phase, c, nil)
	env := baseEnv("GET", "/auth/dev/callback")
	sess := env[rack.RackSession].(map[string]any)
	sess["omniauth.origin"] = "" // empty origin -> stored as nil
	r, err := s.Call(env)
	if err != nil || r.Status != 200 {
		t.Fatalf("callback = %v %v", r, err)
	}
	auth := app.env["omniauth.auth"].(*AuthHash)
	if auth.Provider() != "dev" {
		t.Fatalf("provider = %q", auth.Provider())
	}
	if app.env["omniauth.origin"] != nil {
		t.Fatalf("empty origin should be nil, got %v", app.env["omniauth.origin"])
	}
}

func TestStrategyCallbackShortCircuitResponse(t *testing.T) {
	c := DefaultConfig()
	phase := func(name, phase string, env any) PhaseResult {
		r := redirect("/somewhere")
		return PhaseResult{Response: &r}
	}
	app := &recordApp{}
	s := NewStrategy("dev", app, phase, c, nil)
	r, err := s.Call(baseEnv("GET", "/auth/dev/callback"))
	if err != nil || r.Status != 302 || app.called {
		t.Fatalf("short-circuit = %v %v called=%v", r, err, app.called)
	}
}

func TestStrategyCallbackFail(t *testing.T) {
	c := DefaultConfig()
	phase := func(name, phase string, env any) PhaseResult {
		return PhaseResult{Fail: "invalid_credentials"}
	}
	s := NewStrategy("dev", &recordApp{}, phase, c, nil)
	r, _ := s.Call(baseEnv("GET", "/auth/dev/callback"))
	if !strings.Contains(header(r, "location"), "message=invalid_credentials") {
		t.Fatalf("fail = %q", header(r, "location"))
	}
}

func TestStrategyCallbackSessionNotMap(t *testing.T) {
	c := DefaultConfig()
	app := &recordApp{}
	s := NewStrategy("dev", app, okRequestPhase("/p"), c, nil)
	env := baseEnv("GET", "/auth/dev/callback")
	env[rack.RackSession] = "not-a-map" // present (passes RequireSession) but not a map
	if _, err := s.Call(env); err != nil {
		t.Fatalf("err = %v", err)
	}
	if p, ok := app.env["omniauth.params"].(map[string]any); !ok || len(p) != 0 {
		t.Fatalf("params default = %v", app.env["omniauth.params"])
	}
}

// --- Strategy: OPTIONS & options paths -------------------------------------

func TestStrategyOptionsRequest(t *testing.T) {
	c := DefaultConfig()
	c.AllowedRequestMethods = []string{"GET", "POST"}
	s := NewStrategy("dev", &recordApp{}, okRequestPhase("/p"), c, nil)
	r, err := s.Call(baseEnv("OPTIONS", "/auth/dev"))
	if err != nil || r.Status != 200 {
		t.Fatalf("options = %v %v", r, err)
	}
	if header(r, "allow") != "GET, POST" {
		t.Fatalf("allow = %q", header(r, "allow"))
	}
}

func TestStrategyCustomPaths(t *testing.T) {
	c := DefaultConfig()
	opts := &Options{PathPrefix: "/oauth", RequestPath: "/login/dev", CallbackPath: "/login/dev/back"}
	s := NewStrategy("dev", &recordApp{}, okRequestPhase("/p"), c, opts)
	// custom request path, with a trailing slash to exercise currentPath stripping
	r, err := s.Call(baseEnv("POST", "/login/dev/"))
	if err != nil || r.Status != 302 {
		t.Fatalf("custom request = %v %v", r, err)
	}
	// custom callback path routes to the callback phase
	app := &recordApp{}
	sc := NewStrategy("dev", app, okRequestPhase("/p"), c, opts)
	if _, err := sc.Call(baseEnv("GET", "/login/dev/back")); err != nil || !app.called {
		t.Fatalf("custom callback = %v called=%v", err, app.called)
	}
	// pathPrefix override alone (no custom request/callback) is exercised here:
	s2 := NewStrategy("dev", &recordApp{}, okRequestPhase("/p"), c, &Options{PathPrefix: "/oauth"})
	if got := s2.requestPathValue(); got != "/oauth/dev" {
		t.Fatalf("prefix override path = %q", got)
	}
	if got := s2.callbackPathValue(); got != "/oauth/dev/callback" {
		t.Fatalf("prefix override callback = %q", got)
	}
}

// --- Strategy: mock / test mode --------------------------------------------

func TestStrategyMockRequestRedirect(t *testing.T) {
	c := DefaultConfig()
	c.TestMode = true
	s := NewStrategy("dev", &recordApp{}, nil, c, nil)
	// with query string
	env := baseEnv("POST", "/auth/dev")
	env[rack.QueryString] = "origin=%2Fx"
	r, _ := s.Call(env)
	if r.Status != 302 || header(r, "location") != "/auth/dev/callback?origin=%2Fx" {
		t.Fatalf("mock request = %q", header(r, "location"))
	}
	// without query string
	r2, _ := s.Call(baseEnv("POST", "/auth/dev"))
	if header(r2, "location") != "/auth/dev/callback" {
		t.Fatalf("mock request no qs = %q", header(r2, "location"))
	}
}

func TestStrategyMockCallbackSuccessDefault(t *testing.T) {
	c := DefaultConfig()
	c.TestMode = true
	c.MockAuth["default"] = AuthHashOf("uid", "mock-uid")
	app := &recordApp{}
	s := NewStrategy("dev", app, nil, c, nil)
	r, err := s.Call(baseEnv("GET", "/auth/dev/callback"))
	if err != nil || r.Status != 200 || !app.called {
		t.Fatalf("mock callback = %v %v", r, err)
	}
	auth := app.env["omniauth.auth"].(*AuthHash)
	if auth.Provider() != "dev" || auth.UID() != "mock-uid" {
		t.Fatalf("mock auth = %#v", auth)
	}
}

func TestStrategyMockCallbackNamed(t *testing.T) {
	c := DefaultConfig()
	c.TestMode = true
	c.MockAuth["dev"] = AuthHashOf("uid", "named")
	app := &recordApp{}
	s := NewStrategy("dev", app, nil, c, nil)
	if _, err := s.Call(baseEnv("GET", "/auth/dev/callback")); err != nil {
		t.Fatalf("err = %v", err)
	}
	if app.env["omniauth.auth"].(*AuthHash).UID() != "named" {
		t.Fatal("named mock")
	}
}

func TestStrategyMockCallbackNoMock(t *testing.T) {
	c := DefaultConfig()
	c.TestMode = true
	s := NewStrategy("dev", &recordApp{}, nil, c, nil)
	r, _ := s.Call(baseEnv("GET", "/auth/dev/callback"))
	if !strings.Contains(header(r, "location"), "message=invalid_credentials") {
		t.Fatalf("no mock = %q", header(r, "location"))
	}
}

func TestStrategyMockCallbackFailure(t *testing.T) {
	c := DefaultConfig()
	c.TestMode = true
	c.MockFailure["dev"] = "access_denied"
	s := NewStrategy("dev", &recordApp{}, nil, c, nil)
	r, _ := s.Call(baseEnv("GET", "/auth/dev/callback"))
	if !strings.Contains(header(r, "location"), "message=access_denied") {
		t.Fatalf("mock failure = %q", header(r, "location"))
	}
}

func TestStrategyMockPassthrough(t *testing.T) {
	c := DefaultConfig()
	c.TestMode = true
	app := &recordApp{}
	s := NewStrategy("dev", app, nil, c, nil)
	r, err := s.Call(baseEnv("GET", "/unrelated"))
	if err != nil || r.Status != 200 || !app.called {
		t.Fatalf("mock passthrough = %v %v", r, err)
	}
}

// --- End-to-end via Builder ------------------------------------------------

func TestEndToEndBuilder(t *testing.T) {
	c := DefaultConfig()
	reg := NewStrategies()
	reg.Register("dev", okRequestPhase("https://dev/authorize"))
	app := &recordApp{}
	built, err := NewBuilder(c, reg).Provider("dev", nil).Build(app)
	if err != nil {
		t.Fatalf("build = %v", err)
	}
	// request phase
	r, err := built.Call(baseEnv("POST", "/auth/dev"))
	if err != nil || r.Status != 302 {
		t.Fatalf("e2e request = %v %v", r, err)
	}
	// callback phase reaches the app with an auth hash
	if _, err := built.Call(baseEnv("GET", "/auth/dev/callback")); err != nil {
		t.Fatalf("e2e callback = %v", err)
	}
	if !app.called {
		t.Fatal("app not reached in callback")
	}
}
