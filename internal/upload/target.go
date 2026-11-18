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
	// Problem, when set, is why nothing may be uploaded for this target.
	Problem string
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

// DetectTarget fills in what the flags left empty. The scanned directory's
// own git remote names the repository; GitHub Actions' context (branch,
// default branch, commit, pull request) is used only when that repository
// is the workflow's own, so scanning another checkout never files findings
// under the workflow's repository or branch.
func DetectTarget(dir string, flags Target, env Env) Target {
	t := flags
	remote := ""
	if r, err := gitRunner(dir, "remote", "get-url", "origin"); err == nil {
		remote = NormalizeRepository(r)
	}
	ghRepo := ""
	if srv, repo := env("GITHUB_SERVER_URL"), env("GITHUB_REPOSITORY"); srv != "" && repo != "" {
		ghRepo = NormalizeRepository(strings.TrimSuffix(srv, "/") + "/" + repo)
	}
	if t.Repository == "" {
		t.Repository = remote
		if t.Repository == "" {
			t.Repository = ghRepo
		}
	}
	t.Repository = NormalizeRepository(t.Repository)
	useGH := ghRepo != "" && strings.EqualFold(t.Repository, ghRepo)
	var ev ghEvent
	if useGH {
		ev = readEvent(env)
	}

	if t.DefaultBranch == "" && useGH {
		t.DefaultBranch = ev.Repository.DefaultBranch
	}
	if t.DefaultBranch == "" {
		if ref, err := gitRunner(dir, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"); err == nil {
			t.DefaultBranch = strings.TrimPrefix(ref, "origin/")
		}
	}

	if t.Branch == "" {
		switch {
		case useGH && env("GITHUB_HEAD_REF") != "": // pull_request / pull_request_target
			t.Branch, t.Problem = prBranch(env, ev, t.DefaultBranch)
		case useGH && env("GITHUB_REF_TYPE") == "branch" && env("GITHUB_REF_NAME") != "":
			t.Branch = env("GITHUB_REF_NAME")
		default:
			if b, err := gitRunner(dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil && b != "HEAD" {
				t.Branch = b
			}
		}
	}

	if t.CommitSHA == "" {
		if sha, err := gitRunner(dir, "rev-parse", "HEAD"); err == nil {
			t.CommitSHA = sha
		} else if useGH {
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

var pullRef = regexp.MustCompile(`^refs/(pull/[0-9]+/(?:merge|head))$`)

// prBranch picks the branch a pull request's findings are filed under. The
// head branch name is used only for a same-repository PR whose head is not
// the default branch. A PR from a fork (or one whose origin cannot be
// confirmed), or whose head is named like the default branch, is filed under
// its own pull/<N>/merge scope instead: a contributor's branch "main" must
// never become the default branch's full run.
func prBranch(env Env, ev ghEvent, defaultBranch string) (branch, problem string) {
	head := env("GITHUB_HEAD_REF")
	headRepo, baseRepo := ev.PullRequest.Head.Repo.FullName, ev.Repository.FullName
	sameRepo := headRepo != "" && baseRepo != "" && strings.EqualFold(headRepo, baseRepo)
	if sameRepo && head != defaultBranch {
		return head, ""
	}
	if m := pullRef.FindStringSubmatch(env("GITHUB_REF")); m != nil {
		return m[1], ""
	}
	return "", "pull request from a fork (or with a head branch named like the default branch) and no refs/pull/<N> ref to scope it by: refusing to upload so it cannot land in the default branch's findings (pass --branch to override)"
}

type ghEvent struct {
	Repository struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	PullRequest struct {
		Head struct {
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
}

// readEvent reads the Actions event payload, when there is one.
func readEvent(env Env) ghEvent {
	var ev ghEvent
	if p := env("GITHUB_EVENT_PATH"); p != "" {
		if raw, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(raw, &ev)
		}
	}
	return ev
}
