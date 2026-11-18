package upload

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Endpoint is the platform's SARIF import route
// (backend/routes/cicd_scan_routes.py upload_sarif, mounted under /api).
const Endpoint = "/api/cicd/sarif/upload"

// Environment variables.
const (
	EnvURL    = "OFFLOAD_URL"
	EnvAPIKey = "OFFLOAD_API_KEY"
	EnvCACert = "OFFLOAD_CA_CERT"
)

// Retry policy: bounded, for 408/429/5xx and network errors.
const (
	maxAttempts   = 4
	maxRetryAfter = 60 * time.Second
	// Just over the platform's 300 s body deadline, so its 408 (which names
	// the limit) arrives before a client timeout.
	requestTimeout = 330 * time.Second
)

// Config is a validated upload configuration.
type Config struct {
	BaseURL string // scheme://host[:port][/path], no trailing slash, no /api
	APIKey  string
	Client  *http.Client
	// Sleep and Backoff are swapped in tests.
	Sleep   func(time.Duration)
	Backoff func(attempt int) time.Duration
}

// ConfigError is a configuration problem found before anything is sent.
type ConfigError struct{ msg string }

func (e *ConfigError) Error() string { return e.msg }

// NewConfig validates the platform URL, the API key (from OFFLOAD_API_KEY
// only, never a flag) and the optional CA bundle (OFFLOAD_CA_CERT).
func NewConfig(platformURL string, env Env) (*Config, error) {
	if platformURL == "" {
		platformURL = env(EnvURL)
	}
	if platformURL == "" {
		return nil, &ConfigError{"--upload needs the platform URL: pass --platform-url or set " + EnvURL}
	}
	base, err := normalizeBaseURL(platformURL)
	if err != nil {
		return nil, &ConfigError{err.Error()}
	}
	key := strings.TrimSpace(env(EnvAPIKey))
	if key == "" {
		return nil, &ConfigError{"--upload needs a CI/CD API key in the " + EnvAPIKey +
			" environment variable (it is never read from a flag, so it stays out of shell history and ps)"}
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca := env(EnvCACert); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, &ConfigError{fmt.Sprintf("%s: cannot read %s: %v", EnvCACert, ca, err)}
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &ConfigError{fmt.Sprintf("%s: no PEM certificates found in %s", EnvCACert, ca)}
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &Config{
		BaseURL: base,
		APIKey:  key,
		Client: &http.Client{
			Transport: tr,
			Timeout:   requestTimeout,
			// Never follow a redirect: it would re-send the API key to
			// wherever the redirect points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Sleep:   time.Sleep,
		Backoff: func(attempt int) time.Duration { return time.Duration(1<<attempt) * time.Second },
	}, nil
}

// normalizeBaseURL accepts "https://host", "https://host/" or
// "https://host/api" and refuses plain http to anything but loopback (the
// API key would travel in clear text).
func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("platform URL %q must be an absolute https:// URL, e.g. https://offload.example.com", raw)
	}
	if u.User != nil {
		return "", errors.New("platform URL must not carry credentials; the API key goes in " + EnvAPIKey)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("refusing to send the API key over plain http to %s: use https", u.Host)
	}
	p := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api")
	return u.Scheme + "://" + u.Host + strings.TrimSuffix(p, "/"), nil
}

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Result is the platform's ingest summary for one or more POSTs.
type Result struct {
	Uploads  []IngestData
	Warnings []string
}

// IngestData is the `data` of a successful upload (cicd_integration_service.ingest_sarif).
type IngestData struct {
	UploadID        string       `json:"upload_id"`
	Repository      string       `json:"repository"`
	ScopeKey        string       `json:"scope_key"`
	BranchScope     bool         `json:"branch_scope"`
	BranchScopeNote string       `json:"branch_scope_note"`
	FullRun         bool         `json:"full_run"`
	Branch          string       `json:"branch"`
	ResultsInLog    int          `json:"results_in_log"`
	Tools           []IngestTool `json:"tools"`
}

// IngestTool is the per-tool summary.
type IngestTool struct {
	Tool              string `json:"tool"`
	Scanner           string `json:"scanner"`
	ResultsReceived   int    `json:"results_received"`
	ResultsIngested   int    `json:"results_ingested"`
	New               int    `json:"new"`
	Updated           int    `json:"updated"`
	Reopened          int    `json:"reopened"`
	Resolved          int    `json:"resolved"`
	ResolvedOnAbsence bool   `json:"resolved_on_absence"`
	SkippedReason     string `json:"absence_resolution_skipped"`
}

// Error is an upload failure, with a message per error class.
type Error struct {
	Status int // HTTP status, 0 for a transport failure
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

type envelope struct {
	Success *bool           `json:"success"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
	Detail  interface{}     `json:"detail"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// serverMessage extracts the platform's error text ({success:false,
// error:{message}}, or FastAPI's {detail}).
func serverMessage(body []byte) string {
	var env envelope
	if json.Unmarshal(body, &env) == nil {
		switch {
		case env.Error != nil && env.Error.Message != "":
			return env.Error.Message
		case env.Detail != nil:
			if s, ok := env.Detail.(string); ok {
				return s
			}
			b, _ := json.Marshal(env.Detail)
			return string(b)
		case env.Message != "":
			return env.Message
		}
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// Upload sends the plan: one combined log, or one log per tool when the
// combined log is over the platform's default limits or the server answers
// 413. A single tool's log that is still too large fails with its count;
// nothing is ever cut.
func Upload(cfg *Config, p *Plan, t Target) (*Result, error) {
	res := &Result{}
	fullRun := t.Branch != ""
	if !fullRun {
		res.Warnings = append(res.Warnings, "branch unknown: sent as a partial upload, so findings absent from this scan are NOT resolved on the platform (pass --branch)")
	}
	batches := []Batch{p.whole}
	if p.needsSplit() || len(p.perTool) == 1 {
		batches = p.perTool
	}
	for i := 0; i < len(batches); i++ {
		b := batches[i]
		data, err := post(cfg, b, t, fullRun, res)
		var ue *Error
		if errors.As(err, &ue) && ue.Status == http.StatusRequestEntityTooLarge && len(b.Tools) > 1 {
			res.Warnings = append(res.Warnings, "the platform refused the combined upload as too large; sending one upload per tool")
			batches = append(batches[:i:i], p.perTool...)
			i--
			continue
		}
		if err != nil {
			if ue != nil && ue.Status == http.StatusRequestEntityTooLarge {
				ue.Msg = fmt.Sprintf("upload too large: %s (%d results, %d bytes): %s", strings.Join(b.Tools, ","), b.Results, len(b.Body), ue.Msg)
			}
			return res, err
		}
		res.Uploads = append(res.Uploads, *data)
	}
	return res, nil
}

func post(cfg *Config, b Batch, t Target, fullRun bool, res *Result) (*IngestData, error) {
	data, err := postOnce(cfg, b, t, fullRun)
	var ue *Error
	// A full run on a branch needs the default branch; when the platform
	// cannot determine it, it refuses (400). Retry as a partial upload and
	// say so: absent findings are then not resolved.
	if fullRun && errors.As(err, &ue) && ue.Status == http.StatusBadRequest &&
		strings.Contains(ue.Msg, "default_branch") {
		res.Warnings = append(res.Warnings, "the platform does not know this repository's default branch: sent as a partial upload, so findings absent from this scan are NOT resolved (pass --default-branch)")
		return postOnce(cfg, b, t, false)
	}
	return data, err
}

func postOnce(cfg *Config, b Batch, t Target, fullRun bool) (*IngestData, error) {
	q := url.Values{}
	q.Set("repository", t.Repository)
	if t.Branch != "" {
		q.Set("branch", t.Branch)
	}
	if t.DefaultBranch != "" {
		q.Set("default_branch", t.DefaultBranch)
	}
	if t.CommitSHA != "" {
		q.Set("commit_sha", t.CommitSHA)
	}
	q.Set("full_run", strconv.FormatBool(fullRun))
	endpoint := cfg.BaseURL + Endpoint + "?" + q.Encode()

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b.Body))
		if err != nil {
			return nil, &Error{Msg: "building request: " + err.Error()}
		}
		req.Header.Set("X-API-Key", cfg.APIKey)
		req.Header.Set("Content-Type", "application/sarif+json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "offload-cli")

		resp, err := cfg.Client.Do(req)
		if err != nil {
			lastErr = &Error{Msg: fmt.Sprintf("cannot reach the platform at %s: %v", cfg.BaseURL, redactErr(err, cfg.APIKey))}
			if attempt < maxAttempts {
				cfg.Sleep(cfg.Backoff(attempt))
				continue
			}
			return nil, lastErr
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		msg := redact(serverMessage(body), cfg.APIKey)

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			var env envelope
			if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 || string(env.Data) == "null" {
				return nil, &Error{Status: resp.StatusCode, Msg: fmt.Sprintf("unexpected response from %s (HTTP %d): not the platform's {success, data} envelope — check %s", cfg.BaseURL, resp.StatusCode, EnvURL)}
			}
			if env.Success != nil && !*env.Success {
				return nil, &Error{Status: resp.StatusCode, Msg: "the platform reported failure: " + msg}
			}
			var d IngestData
			if err := json.Unmarshal(env.Data, &d); err != nil {
				return nil, &Error{Status: resp.StatusCode, Msg: "unreadable ingest summary: " + err.Error()}
			}
			return &d, nil
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			return nil, &Error{Status: resp.StatusCode, Msg: fmt.Sprintf("the platform redirected the upload to %q (HTTP %d); redirects are not followed so the API key is never re-sent — set %s to the final URL", resp.Header.Get("Location"), resp.StatusCode, EnvURL)}
		case retryable(resp.StatusCode):
			lastErr = classify(resp.StatusCode, msg, cfg.BaseURL)
			if attempt == maxAttempts {
				return nil, lastErr
			}
			wait := cfg.Backoff(attempt)
			if ra := retryAfter(resp.Header.Get("Retry-After")); ra > 0 {
				if ra > maxRetryAfter {
					return nil, &Error{Status: resp.StatusCode, Msg: fmt.Sprintf("%s (the platform asks to retry in %s; not waiting that long)", lastErr.Error(), ra)}
				}
				wait = ra
			}
			cfg.Sleep(wait)
		default:
			return nil, classify(resp.StatusCode, msg, cfg.BaseURL)
		}
	}
	return nil, lastErr
}

func retryable(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func retryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func classify(code int, msg, base string) *Error {
	var m string
	switch code {
	case http.StatusUnauthorized:
		m = "the platform rejected the API key (invalid, revoked or expired): " + msg +
			". Create a key under your profile menu → API Keys with the \"CI/CD Pipeline\" preset and set it in " + EnvAPIKey
	case http.StatusForbidden:
		m = "the API key is not allowed to upload: it needs the scans:trigger scope (the CI/CD Pipeline presets include it), and its owner needs the Run Scans permission. Platform said: " + msg
	case http.StatusNotFound:
		m = fmt.Sprintf("%s%s not found: check %s points at an Offload platform with SARIF import", base, Endpoint, EnvURL)
	case http.StatusRequestEntityTooLarge:
		m = msg
	case http.StatusTooManyRequests:
		m = "rate limited by the platform (60 SARIF uploads an hour per key, 2 in transfer at once): " + msg
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		m = "the platform refused the upload: " + msg
	case http.StatusRequestTimeout:
		m = "the platform timed out receiving the upload: " + msg
	default:
		m = fmt.Sprintf("the platform returned HTTP %d: %s", code, msg)
	}
	return &Error{Status: code, Msg: m}
}

// redact removes the API key from any text that is about to be printed.
func redact(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "[REDACTED]")
}

func redactErr(err error, key string) string { return redact(err.Error(), key) }
