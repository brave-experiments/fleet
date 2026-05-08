// Package gitpolicy enforces an execution policy sourced from a git repository.
// When active, orbit only executes scripts whose name exists in the policy
// repository, and always runs the content from git — not from the Fleet server.
// This ensures a compromised Fleet server cannot run arbitrary code: it can
// only trigger execution of scripts that a human already committed to git
// (which the caller should protect with branch protection + commit signing).
//
// The repository must contain a directory of approved scripts (default:
// "scripts/"). Script files with extensions .sh, .ps1, and .py are indexed by
// their basename (e.g. "collect-logs.sh"). When Fleet requests execution of
// "collect-logs.sh", orbit reads that file from git and runs it, ignoring the
// content that Fleet sent. Scripts without a name (anonymous / ad-hoc
// executions) are always blocked.
package gitpolicy

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// allowedExtensions mirrors the extensions Fleet itself accepts for scripts.
var allowedExtensions = map[string]bool{
	".sh":  true,
	".ps1": true,
	".py":  true,
}

// Enforcer syncs a git repository and serves approved script content from it.
//
// The repository is expected to look like:
//
//	<repo>/
//	  scripts/                         (configurable via scriptsDir)
//	    <script-name>.{sh,ps1,py}      regular & setup-experience scripts
//	    installers/<software-title>/   software-installer scripts
//	      install.{sh,ps1}
//	      post-install.{sh,ps1}
//	      uninstall.{sh,ps1}
//	  extensions.allowlist             one allowed osquery extension name per line
type Enforcer struct {
	repoURL    string
	repoBranch string
	repoDir    string
	scriptsDir string // subdirectory within the repo that holds approved scripts
	interval   time.Duration

	mu                sync.RWMutex
	scripts           map[string][]byte           // script basename → file contents
	installerScripts  map[string]map[string][]byte // title → kind ("install"|"post-install"|"uninstall") → contents
	allowedExtensions map[string]struct{}         // extension name set
}

// New creates an Enforcer. scriptsDir is the path within the cloned repo
// (relative to its root) where approved scripts live, e.g. "scripts".
func New(repoURL, repoBranch, repoDir, scriptsDir string, interval time.Duration) *Enforcer {
	return &Enforcer{
		repoURL:    repoURL,
		repoBranch: repoBranch,
		repoDir:    repoDir,
		scriptsDir: scriptsDir,
		interval:   interval,
	}
}

// Start performs an initial sync (blocking), then re-syncs on interval until
// ctx is done. Returns an error only if the initial sync fails.
func (e *Enforcer) Start(ctx context.Context) error {
	if err := e.sync(ctx); err != nil {
		return fmt.Errorf("initial git policy sync: %w", err)
	}

	go func() {
		ticker := time.NewTicker(e.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := e.sync(ctx); err != nil {
					log.Warn().Err(err).Msg("git policy sync failed, retaining cached scripts")
				}
			}
		}
	}()

	return nil
}

func (e *Enforcer) sync(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(e.repoDir, ".git")); os.IsNotExist(err) {
		if err := os.MkdirAll(e.repoDir, 0o700); err != nil {
			return fmt.Errorf("create repo dir: %w", err)
		}
		out, err := exec.CommandContext(ctx, "git", "clone",
			"--depth", "1",
			"--branch", e.repoBranch,
			e.repoURL, e.repoDir,
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git clone: %w: %s", err, strings.TrimSpace(string(out)))
		}
	} else {
		out, err := exec.CommandContext(ctx, "git",
			"-C", e.repoDir,
			"fetch", "--depth", "1", "origin", e.repoBranch,
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git fetch: %w: %s", err, strings.TrimSpace(string(out)))
		}
		out, err = exec.CommandContext(ctx, "git",
			"-C", e.repoDir,
			"reset", "--hard", "FETCH_HEAD",
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git reset: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return e.buildIndex()
}

func (e *Enforcer) buildIndex() error {
	scriptsPath := filepath.Join(e.repoDir, e.scriptsDir)
	installersPath := filepath.Join(scriptsPath, "installers")

	newScripts := make(map[string][]byte)
	newInstallers := make(map[string]map[string][]byte)
	// A missing scripts directory means an empty index, which blocks everything.
	// That's the safe default — do not error out.
	if _, statErr := os.Stat(scriptsPath); os.IsNotExist(statErr) {
		return e.applyIndex(newScripts, newInstallers)
	}
	err := filepath.WalkDir(scriptsPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !allowedExtensions[ext] {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read script %s: %w", path, err)
		}
		// Files under scripts/installers/<title>/<kind>.<ext> are software-installer
		// scripts indexed by title and kind, not by basename.
		if rel, ok := stripPrefix(path, installersPath); ok {
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) == 2 {
				title := parts[0]
				kind := strings.TrimSuffix(parts[1], ext)
				if newInstallers[title] == nil {
					newInstallers[title] = make(map[string][]byte)
				}
				newInstallers[title][kind] = content
			}
			return nil
		}
		newScripts[filepath.Base(path)] = content
		return nil
	})
	if err != nil {
		return fmt.Errorf("index scripts dir %s: %w", scriptsPath, err)
	}

	return e.applyIndex(newScripts, newInstallers)
}

// applyIndex finishes loading the allowlists and atomically swaps in the new index.
func (e *Enforcer) applyIndex(scripts map[string][]byte, installers map[string]map[string][]byte) error {
	allowedExts, err := loadExtensionsAllowlist(filepath.Join(e.repoDir, "extensions.allowlist"))
	if err != nil {
		return fmt.Errorf("load extensions allowlist: %w", err)
	}

	e.mu.Lock()
	e.scripts = scripts
	e.installerScripts = installers
	e.allowedExtensions = allowedExts
	e.mu.Unlock()

	log.Info().
		Int("scripts", len(scripts)).
		Int("installers", len(installers)).
		Int("extensions", len(allowedExts)).
		Msg("git policy index updated")
	return nil
}

// stripPrefix returns the path with prefix removed, plus whether the prefix matched.
// Used to detect files inside the installers/ subdirectory.
func stripPrefix(path, prefix string) (string, bool) {
	rel, err := filepath.Rel(prefix, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return rel, true
}

// loadExtensionsAllowlist reads a newline-separated list of allowed osquery
// extension names. Comments (#) and blank lines are ignored. A missing file
// produces an empty (but non-nil) set, which means "no extensions allowed" —
// safer default than allowing everything when the file is forgotten.
func loadExtensionsAllowlist(path string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return allowed, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allowed[line] = struct{}{}
	}
	return allowed, nil
}

// GetApprovedContent returns the content of the approved script with the given
// basename from the git repository. Returns (nil, false) if the script is not
// in the repository, meaning execution should be blocked.
func (e *Enforcer) GetApprovedContent(name string) ([]byte, bool) {
	e.mu.RLock()
	scripts := e.scripts
	e.mu.RUnlock()

	if scripts == nil {
		log.Warn().Str("name", name).Msg("git policy index not yet loaded; blocking execution")
		return nil, false
	}

	content, found := scripts[name]
	if !found {
		log.Error().Str("name", name).Msg("git policy: script not in repository; blocking execution")
	}
	return content, found
}

// GetApprovedInstallerScript returns the content of the approved installer
// script for the given software title and kind ("install", "post-install", or
// "uninstall"). Returns (nil, false) if the title or kind is not present in
// the repository.
func (e *Enforcer) GetApprovedInstallerScript(title, kind string) ([]byte, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.installerScripts == nil {
		log.Warn().Str("title", title).Msg("git policy index not yet loaded; blocking installer")
		return nil, false
	}
	scripts, ok := e.installerScripts[title]
	if !ok {
		return nil, false
	}
	content, ok := scripts[kind]
	return content, ok
}

// AllowedExtensions returns the set of osquery extension names approved by the
// policy repository. A nil return means the index has not loaded yet (caller
// should treat that as "block all"); an empty non-nil map means "no extensions
// allowed".
func (e *Enforcer) AllowedExtensions() map[string]struct{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.allowedExtensions == nil {
		return nil
	}
	// Return a copy so callers can't mutate our state.
	out := make(map[string]struct{}, len(e.allowedExtensions))
	for k := range e.allowedExtensions {
		out[k] = struct{}{}
	}
	return out
}
