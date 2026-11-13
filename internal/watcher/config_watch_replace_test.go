package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

// replaceConfigByRename mimics `sed -i` and editor atomic saves: the new
// content is written to a sibling temp file which is renamed over target.
func replaceConfigByRename(t *testing.T, target string, cfg *config.Config) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".config-*.tmp")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	if _, err = tmp.Write(data); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	if err = tmp.Close(); err != nil {
		t.Fatalf("failed to close temp config: %v", err)
	}
	if err = os.Rename(tmp.Name(), target); err != nil {
		t.Fatalf("failed to rename config: %v", err)
	}
}

func waitForReloadedPort(t *testing.T, ports <-chan int, want int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case port := <-ports:
			if port == want {
				return
			}
		case <-deadline:
			t.Fatalf("config replaced by rename was not reloaded (want port %d)", want)
		}
	}
}

func startConfigReplaceWatcher(t *testing.T, configPath, writePath, authDir string) <-chan int {
	t.Helper()
	base := &config.Config{Port: 9000, AuthDir: authDir, CredentialInFlight: config.DefaultCredentialInFlightConfig()}
	replaceConfigByRename(t, writePath, base)
	ports := make(chan int, 16)
	w, err := NewWatcher(configPath, authDir, func(cfg *config.Config) {
		if cfg != nil {
			ports <- cfg.Port
		}
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	w.SetConfig(base)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = w.Stop()
		w.stopConfigReloadTimer()
	})
	if err = w.Start(ctx); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	waitForReloadedPort(t, ports, 9000)
	return ports
}

func TestConfigReloadSurvivesRepeatedRenameReplace(t *testing.T) {
	tmpDir := t.TempDir()
	authDir := filepath.Join(tmpDir, "auth")
	if err := os.MkdirAll(authDir, 0o755); err != nil {
		t.Fatalf("failed to create auth dir: %v", err)
	}
	configPath := filepath.Join(tmpDir, "config.yaml")
	ports := startConfigReplaceWatcher(t, configPath, configPath, authDir)

	for _, port := range []int{9101, 9102} {
		replaceConfigByRename(t, configPath, &config.Config{Port: port, AuthDir: authDir, CredentialInFlight: config.DefaultCredentialInFlightConfig()})
		waitForReloadedPort(t, ports, port)
	}
}

func TestConfigReloadSurvivesRenameReplaceOfSymlinkTarget(t *testing.T) {
	tmpDir := t.TempDir()
	authDir := filepath.Join(tmpDir, "auth")
	targetDir := filepath.Join(tmpDir, "target")
	linkDir := filepath.Join(tmpDir, "link")
	for _, dir := range []string{authDir, targetDir, linkDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create %s: %v", dir, err)
		}
	}
	targetPath := filepath.Join(targetDir, "config.yaml")
	configPath := filepath.Join(linkDir, "config.yaml")
	if err := os.WriteFile(targetPath, []byte("port: 1\n"), 0o644); err != nil {
		t.Fatalf("failed to seed target: %v", err)
	}
	if err := os.Symlink(targetPath, configPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	ports := startConfigReplaceWatcher(t, configPath, targetPath, authDir)

	for _, port := range []int{9201, 9202} {
		replaceConfigByRename(t, targetPath, &config.Config{Port: port, AuthDir: authDir, CredentialInFlight: config.DefaultCredentialInFlightConfig()})
		waitForReloadedPort(t, ports, port)
	}
}
