// Command testprobe is a TEST-ONLY helper for the Python↔Go contract suite
// (tests/test_milestone_b_parity.py). It exercises the auth package across
// the process boundary in both directions. Never shipped, never served.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"webshare-core/internal/auth"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "pwverify":
		err = runPWVerify(os.Args[2:])
	case "pwhash":
		err = runPWHash(os.Args[2:])
	case "sessign":
		err = runSesSign(os.Args[2:])
	case "sesverify":
		err = runSesVerify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: testprobe <pwverify|pwhash|sessign|sesverify> ...")
}

func runPWVerify(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("pwverify <stored> <provided>")
	}
	if !auth.VerifyPassword(args[0], args[1]) {
		os.Exit(1)
	}
	return nil
}

func runPWHash(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("pwhash <password>")
	}
	h, err := auth.HashPassword(args[0])
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

func runSesSign(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("sessign <secret> <payload-json>")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(args[1]), &payload); err != nil {
		return err
	}
	cookie, err := (auth.FlaskCodec{Secret: args[0], Salt: auth.SessionCookieSalt}).Sign(payload)
	if err != nil {
		return err
	}
	fmt.Println(cookie)
	return nil
}

func runSesVerify(args []string) error {
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("sesverify <secret> <cookie> [maxage-sec]")
	}
	perm := auth.FlaskPermanentLifetime
	maxAge := &perm
	if len(args) == 3 {
		n, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return err
		}
		d := time.Duration(n) * time.Second
		maxAge = &d
	}
	payload, err := (auth.FlaskCodec{Secret: args[0], Salt: auth.SessionCookieSalt}).Verify(args[1], maxAge, time.Now())
	if err == auth.ErrExpired {
		os.Exit(2)
	}
	if err != nil {
		os.Exit(3)
	}
	raw, _ := json.Marshal(payload)
	fmt.Println(string(raw))
	return nil
}
