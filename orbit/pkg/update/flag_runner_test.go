package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/stretchr/testify/require"
)

var rawJSONFlags = json.RawMessage(`{"verbose":true, "num":5, "hello":"world", "largeNum":1234567890}`)

func TestGetFlagsFromJson(t *testing.T) {
	flagsJson, err := getFlagsFromJSON(rawJSONFlags)
	require.NoError(t, err)

	require.NotEmpty(t, flagsJson)

	value, ok := flagsJson["--verbose"]
	if !ok {
		t.Errorf(`key ""--verbose" expected but not found`)
	}
	if value != "true" {
		t.Errorf(`expected "true", got %s`, value)
	}

	value, ok = flagsJson["--num"]
	if !ok {
		t.Errorf(`key "--num" expected but not found`)
	}
	if value != "5" {
		t.Errorf(`expected "5", got %s`, value)
	}

	value, ok = flagsJson["--hello"]
	if !ok {
		t.Errorf(`key "--hello" expected but not found`)
	}
	if value != "world" {
		t.Errorf(`expected "world", got %s`, value)
	}

	value, ok = flagsJson["--largeNum"]
	if !ok {
		t.Errorf(`key "--largeNum" expected but not found`)
	}
	if value != "1234567890" {
		t.Errorf(`expected "1234567890", got %s`, value)
	}
}

func TestWriteFlagFile(t *testing.T) {
	flags, err := getFlagsFromJSON(rawJSONFlags)
	require.NoError(t, err)

	tempDir := t.TempDir()
	err = writeFlagFile(tempDir, flags)
	require.NoError(t, err)

	diskFlags, err := readFlagFile(tempDir)
	require.NoError(t, err)
	require.NotEmpty(t, diskFlags)

	if !reflect.DeepEqual(flags, diskFlags) {
		t.Errorf("expected flags to be equal: %v, %v", flags, diskFlags)
	}
}

func touchFile(t *testing.T, name string) {
	t.Helper()

	file, err := os.OpenFile(name, os.O_RDONLY|os.O_CREATE, 0o644) // nolint:gosec // G302
	require.NoError(t, err)
	require.NoError(t, file.Close())
}

// TestPolicyActiveForcesDisableDistributed verifies that when ForceDisableDistributed is set,
// orbit overrides whatever the Fleet server sent and writes
// --disable_distributed=true into the osquery flag file.
func TestPolicyActiveForcesDisableDistributed(t *testing.T) {
	rootDir := t.TempDir()

	var restartQueued bool
	queueOrbitRestart := func(string) { restartQueued = true }

	fr := NewFlagReceiver(queueOrbitRestart, FlagUpdateOptions{
		RootDir:                 rootDir,
		PolicyActive: true,
	})

	// Server explicitly sets disable_distributed=false; we must override to true.
	cfg := &fleet.OrbitConfig{
		Flags: json.RawMessage(`{"disable_distributed": false, "verbose": true}`),
	}
	require.NoError(t, fr.Run(cfg))
	require.True(t, restartQueued)

	written, err := readFlagFile(rootDir)
	require.NoError(t, err)
	require.Equal(t, "true", written["--disable_distributed"])
	require.Equal(t, "true", written["--verbose"])
}

// TestPolicyActiveForcesDisableDistributedWithoutServerFlags verifies that the flag file is
// written even when the server sends no flags at all, since we still need to
// enforce --disable_distributed=true.
func TestPolicyActiveForcesDisableDistributedWithoutServerFlags(t *testing.T) {
	rootDir := t.TempDir()

	var restartQueued bool
	queueOrbitRestart := func(string) { restartQueued = true }

	fr := NewFlagReceiver(queueOrbitRestart, FlagUpdateOptions{
		RootDir:                 rootDir,
		PolicyActive: true,
	})

	// Server sends no flags at all.
	cfg := &fleet.OrbitConfig{}
	require.NoError(t, fr.Run(cfg))
	require.True(t, restartQueued)

	written, err := readFlagFile(rootDir)
	require.NoError(t, err)
	require.Equal(t, "true", written["--disable_distributed"])
	require.Len(t, written, 1)
}

// TestPolicyActiveDropsDangerousFlags verifies that flags that could subvert the
// policy (extensions_autoload, config_path, watcher_*) are stripped before
// being written to the flag file.
func TestPolicyActiveDropsDangerousFlags(t *testing.T) {
	rootDir := t.TempDir()
	fr := NewFlagReceiver(func(string) {}, FlagUpdateOptions{
		RootDir:      rootDir,
		PolicyActive: true,
	})

	cfg := &fleet.OrbitConfig{
		Flags: json.RawMessage(`{
			"extensions_autoload": "/tmp/evil.load",
			"config_path": "/tmp/evil.conf",
			"watcher_delay": "10",
			"audit_allow_config": true,
			"disable_watchdog": true,
			"verbose": true
		}`),
	}
	require.NoError(t, fr.Run(cfg))

	written, err := readFlagFile(rootDir)
	require.NoError(t, err)

	// Dangerous flags must have been dropped.
	require.NotContains(t, written, "--extensions_autoload")
	require.NotContains(t, written, "--config_path")
	require.NotContains(t, written, "--watcher_delay")
	require.NotContains(t, written, "--audit_allow_config")
	require.NotContains(t, written, "--disable_watchdog")

	// Innocuous flags must survive, alongside the forced override.
	require.Equal(t, "true", written["--verbose"])
	require.Equal(t, "true", written["--disable_distributed"])
}

// TestPolicyInactivePreservesDefault confirms that when the option
// is OFF, orbit's behaviour is unchanged: empty server flags = no flag file
// rewrite, and server-supplied disable_distributed values are kept verbatim.
func TestPolicyInactivePreservesDefault(t *testing.T) {
	rootDir := t.TempDir()

	fr := NewFlagReceiver(func(string) {}, FlagUpdateOptions{
		RootDir: rootDir,
	})

	// No flags from server, no flag file should be written.
	require.NoError(t, fr.Run(&fleet.OrbitConfig{}))
	_, err := os.Stat(filepath.Join(rootDir, "osquery.flags"))
	require.True(t, os.IsNotExist(err), "flag file should not exist when server sends no flags and override is off")

	// Server sets disable_distributed=false, that value must be preserved.
	require.NoError(t, fr.Run(&fleet.OrbitConfig{
		Flags: json.RawMessage(`{"disable_distributed": false}`),
	}))
	written, err := readFlagFile(rootDir)
	require.NoError(t, err)
	require.Equal(t, "false", written["--disable_distributed"])
}

// TestDoFlagsUpdateWithEmptyFlags tests the scenario of Fleet flag `command_line_flags`
// being set to an empty JSON document `{}` and Orbit osquery.flags file being
// an empty file. Such scenario should trigger no update of flags.
func TestDoFlagsUpdateWithEmptyFlags(t *testing.T) {
	rootDir := t.TempDir()
	osqueryFlagsFile := filepath.Join(rootDir, "osquery.flags")
	touchFile(t, osqueryFlagsFile)

	testConfig := &fleet.OrbitConfig{
		Flags: json.RawMessage("{}"),
	}

	var restartQueued bool
	queueOrbitRestart := func(string) { restartQueued = true }

	fr := NewFlagReceiver(queueOrbitRestart, FlagUpdateOptions{
		RootDir: rootDir,
	})

	err := fr.Run(testConfig)
	require.NoError(t, err)
	require.False(t, restartQueued)

	// Non-empty fleet flags and osquery.flags has empty flags.
	testConfig = &fleet.OrbitConfig{
		Flags: json.RawMessage(`{"--verbose": true}`),
	}
	err = fr.Run(testConfig)
	require.NoError(t, err)
	require.True(t, restartQueued)

	// Empty Fleet flags and osquery.flags has non-empty flags.
	restartQueued = false
	testConfig = &fleet.OrbitConfig{
		Flags: json.RawMessage("{}"),
	}
	err = os.WriteFile(osqueryFlagsFile, []byte("--verbose=true\n"), 0o644)
	require.NoError(t, err)
	err = fr.Run(testConfig)
	require.NoError(t, err)
	require.True(t, restartQueued)
}
