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
type Enforcer struct {
	repoURL    string
	repoBranch string
	repoDir    string
	scriptsDir string // subdirectory within the repo that holds approved scripts
	interval   time.Duration

	mu      sync.RWMutex
	scripts map[string][]byte // script basename → file contents
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

	newScripts := make(map[string][]byte)
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
		name := filepath.Base(path)
		newScripts[name] = content
		return nil
	})
	if err != nil {
		return fmt.Errorf("index scripts dir %s: %w", scriptsPath, err)
	}

	e.mu.Lock()
	e.scripts = newScripts
	e.mu.Unlock()

	log.Info().Int("scripts", len(newScripts)).Str("dir", scriptsPath).Msg("git policy scripts indexed")
	return nil
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
