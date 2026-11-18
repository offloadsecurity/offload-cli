package upload

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Target identifies where the findings belong on the platform.
type Target struct {
	Repository    string // https://host/owner/repo — the platform's scope
	Branch        string
	DefaultBranch string
	CommitSHA     string
	// PathPrefix is the scanned directory's path inside the repository
	// ("" at the root), prepended to finding paths.
	PathPrefix string
}

// Env is the environment lookup (os.Getenv in production).
type Env func(string) string

// gitRunner runs git in dir and returns trimmed stdout (swapped in tests).
var gitRunner = func(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

var (
	scpRemote = regexp.MustCompile(`^(?:[^@/:\s]+@)?([^/:\s]+):(.+)$`)
	hexSHA    = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
)

// NormalizeRepository turns a git remote into the https URL form the
// platform's code scans use (https://host/owner/repo): credentials removed,
// SSH and scp-style remotes rewritten, a trailing ".git" dropped. Anything it
// cannot parse is returned with credentials stripped, for the platform to
// validate.
func NormalizeRepository(remote string) string {
	r := strings.TrimSpace(remote)
	if r == "" {
		return ""
	}
	if !strings.Contains(r, "://") {
		if m := scpRemote.FindStringSubmatch(r); m != nil && !strings.HasPrefix(r, "/") {
			return "https://" + m[1] + "/" + trimRepoPath(m[2])
		}
		return r
	}
	u, err := url.Parse(r)
	if err != nil || u.Host == "" {
		return stripUserinfo(r)
	}
	host := u.Hostname()
	if u.Scheme == "https" || u.Scheme == "http" {
		if p := u.Port(); p != "" {
			host += ":" + p
		}
	}
	// ssh://, git://, git+ssh:// → https on the bare host (an SSH port is
	// not the web port).
	scheme := "https"
	if u.Scheme == "http" {
		scheme = "http"
	}
	return scheme + "://" + host + "/" + trimRepoPath(u.Path)
}

func trimRepoPath(p string) string {
	p = strings.Trim(p, "/")
	return strings.TrimSuffix(p, ".git")
}

// stripUserinfo removes "user:token@" from a URL-ish string.
func stripUserinfo(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		slash := strings.Index(rest, "/")
		at := strings.LastIndex(rest, "@")
		if at >= 0 && (slash < 0 || at < slash) {
			return s[:i+3] + rest[at+1:]
		}
	}
	return s
}

// DetectTarget fills in what the flags left empty: GitHub Actions'
// environment first, then git in dir.
func DetectTarget(dir string, flags Target, env Env) Target {
	t := flags
	if t.Repository == "" {
		if srv, repo := env("GITHUB_SERVER_URL"), env("GITHUB_REPOSITORY"); srv != "" && repo != "" {
			t.Repository = strings.TrimSuffix(srv, "/") + "/" + repo
		} else if remote, err := gitRunner(dir, "remote", "get-url", "origin"); err == nil {
			t.Repository = remote
		}
	}
	t.Repository = NormalizeRepository(t.Repository)

	if t.Branch == "" {
		switch {
		case env("GITHUB_HEAD_REF") != "": // pull_request: the PR's branch
			t.Branch = env("GITHUB_HEAD_REF")
		case env("GITHUB_REF_TYPE") == "branch" && env("GITHUB_REF_NAME") != "":
			t.Branch = env("GITHUB_REF_NAME")
		default:
			if b, err := gitRunner(dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil && b != "HEAD" {
				t.Branch = b
			}
		}
	}

	if t.DefaultBranch == "" {
		t.DefaultBranch = githubDefaultBranch(env)
	}
	if t.DefaultBranch == "" {
		if ref, err := gitRunner(dir, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"); err == nil {
			t.DefaultBranch = strings.TrimPrefix(ref, "origin/")
		}
	}

	if t.CommitSHA == "" {
		if sha, err := gitRunner(dir, "rev-parse", "HEAD"); err == nil {
			t.CommitSHA = sha
		} else {
			t.CommitSHA = env("GITHUB_SHA")
		}
	}
	if !hexSHA.MatchString(t.CommitSHA) {
		t.CommitSHA = "" // the platform accepts only a hex commit id
	}

	if prefix, err := gitRunner(dir, "rev-parse", "--show-prefix"); err == nil {
		t.PathPrefix = strings.TrimSuffix(prefix, "/")
	}
	return t
}

// githubDefaultBranch reads repository.default_branch from the Actions
// event payload, when there is one.
func githubDefaultBranch(env Env) string {
	p := env("GITHUB_EVENT_PATH")
	if p == "" {
		return ""
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var ev struct {
		Repository struct {
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return ""
	}
	return ev.Repository.DefaultBranch
}
