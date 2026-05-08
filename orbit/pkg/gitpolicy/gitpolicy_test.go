package gitpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestEnforcerWithRepo wires an Enforcer to a pre-populated directory
// without going through git, so tests can focus on the indexing logic.
func newTestEnforcerWithRepo(t *testing.T, files map[string]string) *Enforcer {
	t.Helper()
	dir := t.TempDir()
	for rel, contents := range files {
		full := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(contents), 0o644))
	}
	e := New("", "main", dir, "scripts", 0)
	require.NoError(t, e.buildIndex())
	return e
}

func TestIndexScripts(t *testing.T) {
	e := newTestEnforcerWithRepo(t, map[string]string{
		"scripts/collect-logs.sh":  "echo collect",
		"scripts/inventory.py":     "print('hi')",
		"scripts/README.md":        "ignored",
		"scripts/nested/deep.ps1":  "Write-Host deep",
	})

	got, ok := e.GetApprovedContent("collect-logs.sh")
	require.True(t, ok)
	require.Equal(t, "echo collect", string(got))

	got, ok = e.GetApprovedContent("inventory.py")
	require.True(t, ok)
	require.Equal(t, "print('hi')", string(got))

	// Subdirectories are flattened — basename match.
	got, ok = e.GetApprovedContent("deep.ps1")
	require.True(t, ok)
	require.Equal(t, "Write-Host deep", string(got))

	// Non-script files are ignored.
	_, ok = e.GetApprovedContent("README.md")
	require.False(t, ok)

	// Unknown name is blocked.
	_, ok = e.GetApprovedContent("evil.sh")
	require.False(t, ok)
}

func TestIndexInstallerScripts(t *testing.T) {
	e := newTestEnforcerWithRepo(t, map[string]string{
		"scripts/installers/Slack/install.sh":      "echo install",
		"scripts/installers/Slack/post-install.sh": "echo post",
		"scripts/installers/Slack/uninstall.sh":    "echo uninstall",
		"scripts/installers/Chrome/install.ps1":    "Write-Host chrome",
		// Files inside installers should NOT appear in the regular script index.
		"scripts/some-other-script.sh": "regular",
	})

	got, ok := e.GetApprovedInstallerScript("Slack", "install")
	require.True(t, ok)
	require.Equal(t, "echo install", string(got))

	got, ok = e.GetApprovedInstallerScript("Slack", "post-install")
	require.True(t, ok)
	require.Equal(t, "echo post", string(got))

	got, ok = e.GetApprovedInstallerScript("Slack", "uninstall")
	require.True(t, ok)
	require.Equal(t, "echo uninstall", string(got))

	got, ok = e.GetApprovedInstallerScript("Chrome", "install")
	require.True(t, ok)
	require.Equal(t, "Write-Host chrome", string(got))

	// Unknown title or kind is blocked.
	_, ok = e.GetApprovedInstallerScript("EvilApp", "install")
	require.False(t, ok)
	_, ok = e.GetApprovedInstallerScript("Slack", "rollback")
	require.False(t, ok)

	// Regular script lookup must not find installer-keyed files.
	_, ok = e.GetApprovedContent("install.sh")
	require.False(t, ok)
	// But unrelated regular scripts work as before.
	got, ok = e.GetApprovedContent("some-other-script.sh")
	require.True(t, ok)
	require.Equal(t, "regular", string(got))
}

func TestExtensionsAllowlist(t *testing.T) {
	e := newTestEnforcerWithRepo(t, map[string]string{
		"extensions.allowlist": "# managed by infra team\nfleet_extension\n\nlinux-events\n",
	})

	allowed := e.AllowedExtensions()
	require.NotNil(t, allowed)
	require.Contains(t, allowed, "fleet_extension")
	require.Contains(t, allowed, "linux-events")
	require.Len(t, allowed, 2)
}

func TestExtensionsAllowlistMissing(t *testing.T) {
	// Missing allowlist file => empty (non-nil) set => "no extensions allowed".
	e := newTestEnforcerWithRepo(t, map[string]string{})
	allowed := e.AllowedExtensions()
	require.NotNil(t, allowed)
	require.Empty(t, allowed)
}
