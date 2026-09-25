// Command webshare-core is the Go HTTP server core for WebShare Pro.
//
// Milestone A: process skeleton only — no user file routes yet.
// Usage:
//
//	webshare-core serve [--config PATH] [--host H] [--port N] [--parent-pid PID]
//	webshare-core version
//	webshare-core check-config [--config PATH]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"webshare-core/internal/config"
	"webshare-core/internal/files"
	"webshare-core/internal/handlers"
	"webshare-core/internal/permission"
	"webshare-core/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "version":
		fmt.Printf("webshare-core %s (%s/%s)\n", server.Version, runtime.GOOS, runtime.GOARCH)
	case "check-config":
		runCheckConfig(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: webshare-core <serve|version|check-config> [flags]\n")
}

type commonFlags struct {
	configPath string
	host       string
	port       int
	parentPID  int
}

func parseFlags(args []string) commonFlags {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var f commonFlags
	fs.StringVar(&f.configPath, "config", defaultConfigPath(), "path to webshare config JSON")
	fs.StringVar(&f.host, "host", "", "bind host (overrides config display_host)")
	fs.IntVar(&f.port, "port", 0, "bind port (overrides config port)")
	fs.IntVar(&f.parentPID, "parent-pid", 0, "exit when this PID disappears (PyQt launcher)")
	_ = fs.Parse(args)
	return f
}

func defaultConfigPath() string {
	if v := os.Getenv("WEBSHARE_CONFIG"); v != "" {
		return v
	}
	return "webshare_config.json"
}

func runCheckConfig(args []string) {
	f := parseFlags(args)
	path := f.configPath
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ok: %s (folder=%s port=%d)\n", path, cfg.Folder, cfg.Port)
}

func runServe(args []string) {
	f := parseFlags(args)
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Printf("webshare-core %s starting", server.Version)

	cfg, err := config.Load(f.configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}
	host := cfg.DisplayHost
	if f.host != "" {
		host = f.host
	}
	port := cfg.Port
	if f.port != 0 {
		port = f.port
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Readiness gate 1: shared folder exists and is accessible.
	if cfg.Folder == "" {
		log.Fatalf("shared folder is not configured")
	}
	if st, err := os.Stat(cfg.Folder); err != nil || !st.IsDir() {
		log.Fatalf("shared folder unavailable: %s (%v)", cfg.Folder, err)
	}
	if probe, err := os.Open(cfg.Folder); err != nil {
		log.Fatalf("shared folder not accessible: %s (%v)", cfg.Folder, err)
	} else {
		probe.Close()
	}

	control := os.Getenv("WEBSHARE_CONTROL_TOKEN")
	if control == "" {
		log.Printf("warning: WEBSHARE_CONTROL_TOKEN not set, /_control/shutdown disabled")
	}
	// Session secret persistence (parity with ensure_config_secret_key):
	// the config value wins, otherwise the shared secret file. The config
	// file is rewritten only when a missing secret was filled in.
	hadSecret := strings.TrimSpace(cfg.SecretKey) != ""
	if err := config.EnsureSecretKey(&cfg); err != nil {
		log.Fatalf("secret key setup failed: %v", err)
	}
	if !hadSecret {
		if _, err := os.Stat(f.configPath); err == nil {
			if err := config.Save(f.configPath, cfg); err != nil {
				log.Printf("warning: config save failed: %v", err)
			}
		}
	}
	srv := server.New(cfg, control)
	files.IsProtectedRel = permission.IsProtectedSystemPath
	app := handlers.New(cfg, f.configPath)
	if err := app.Perms.Load(); err != nil {
		log.Printf("warning: permission load failed: %v", err)
	}
	srv.RegisterUserRoutes(app.RegisterRoutes)
	srv.SetRuntimeInitialized()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if f.parentPID > 0 {
		go watchParent(ctx, f.parentPID, stop)
	}

	log.Printf("listening on %s (config=%s)", addr, f.configPath)
	if err := srv.Serve(ctx, addr); err != nil {
		log.Fatalf("serve failed: %v", err)
	}
	// Graceful shutdown: drain is handled in Serve; flush persistent
	// runtime state (quota, login blocks, share attempts, audit).
	app.FlushState()
	log.Printf("webshare-core stopped cleanly")
}

// watchParent exits when the launcher PID disappears. Unix: signal-0 poll.
// Windows has no signal-0 equivalent in stdlib, so we log and skip rather
// than pretend to watch.
func watchParent(ctx context.Context, pid int, stop context.CancelFunc) {
	if runtime.GOOS == "windows" {
		log.Printf("parent-pid watch not supported on windows, skipping (pid=%d)", pid)
		return
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !processAlive(pid) {
				log.Printf("parent pid %d gone, shutting down", pid)
				stop()
				return
			}
		}
	}
}
