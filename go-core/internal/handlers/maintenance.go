package handlers

// Periodic maintenance and live config reload for the Go backend.
//
// The Python backend runs server/cleanup.py every 5 minutes (sessions,
// share links, upload sessions, trash auto-delete, login attempts, download
// trackers, dirty flushes). The Go core had no scheduler, so trash
// auto-delete never ran and expired upload temp dirs stayed until the next
// init (audit ISSUE-006). RunMaintenance is that scheduler.

import (
	"context"
	"log"
	"time"

	"webshare-core/internal/config"
	"webshare-core/internal/mutate"
	"webshare-core/internal/permission"
)

// Maintenance cadence mirrors start_periodic_cleanup: first pass one
// minute after start, then every five minutes.
const (
	MaintenanceFirstDelay = time.Minute
	MaintenanceInterval   = 5 * time.Minute
)

// loginAttemptMaxAgeHours mirrors cleanup_expired_login_attempts' default.
const loginAttemptMaxAgeHours = 24

// MaintenanceReport counts what one maintenance pass removed.
type MaintenanceReport struct {
	Sessions, Links, Uploads, Trash, LoginAttempts, Trackers int
}

func (r MaintenanceReport) total() int {
	return r.Sessions + r.Links + r.Uploads + r.Trash + r.LoginAttempts + r.Trackers
}

// RunMaintenance runs MaintenanceOnce after first and then every interval
// until ctx is cancelled.
func (a *App) RunMaintenance(ctx context.Context, first, every time.Duration) {
	timer := time.NewTimer(first)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if r := a.MaintenanceOnce(); r.total() > 0 {
			log.Printf("maintenance: sessions=%d links=%d uploads=%d trash=%d login_attempts=%d trackers=%d",
				r.Sessions, r.Links, r.Uploads, r.Trash, r.LoginAttempts, r.Trackers)
		}
		timer.Reset(every)
	}
}

// MaintenanceOnce performs one cleanup pass (do_cleanup parity).
func (a *App) MaintenanceOnce() MaintenanceReport {
	cfg := a.conf()
	var r MaintenanceReport
	timeout := cfg.SessionTimeout
	if timeout <= 0 {
		timeout = 60
	}
	r.Sessions = a.Sessions.Expire(time.Duration(timeout) * time.Minute)
	r.Links = a.Shares.PurgeExpired()
	expired := a.Uploads.ExpiredIDs()
	removeTempDirs(expired)
	r.Uploads = len(expired)
	days := cfg.TrashAutoDeleteDays
	if days <= 0 {
		days = 30
	}
	r.Trash = mutate.AutoCleanupTrash(cfg.Folder, days)
	r.LoginAttempts = a.Blocks.Cleanup(loginAttemptMaxAgeHours)
	r.Trackers = a.Quota.PurgeStale()
	a.flushAuditIfDirty()
	a.Quota.Flush()
	a.Blocks.Flush()
	a.Shares.FlushAttempts()
	return r
}

// ReloadConfig re-reads the config file and swaps in a new snapshot so GUI
// settings changes (passwords, guest upload, session timeout, limits, IP
// policy, versioning, trash age) apply without a restart (audit ISSUE-007).
// Settings bound at startup — shared folder, bind host/port, HTTPS and the
// session secret — keep their running values; the ones that differ on disk
// are returned so the caller can ask for a restart.
func (a *App) ReloadConfig() ([]string, error) {
	next, err := config.Load(a.ConfigPath)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := a.conf()
	var restart []string
	if permission.CanonicalRoot(next.Folder) != cur.Folder {
		restart = append(restart, "folder")
	}
	if next.DisplayHost != cur.DisplayHost {
		restart = append(restart, "display_host")
	}
	if next.Port != cur.Port {
		restart = append(restart, "port")
	}
	if next.UseHTTPS != cur.UseHTTPS {
		restart = append(restart, "use_https")
	}
	next.Folder = cur.Folder
	next.DisplayHost = cur.DisplayHost
	next.Port = cur.Port
	next.UseHTTPS = cur.UseHTTPS
	next.SecretKey = cur.SecretKey
	a.cfg.Store(&next)
	return restart, nil
}
