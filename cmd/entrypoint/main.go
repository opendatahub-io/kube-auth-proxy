package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func main() {
	// Default mode is rbac
	mode := "rbac"
	args := os.Args[1:]

	// Check environment variable first
	if envMode := os.Getenv("PROXY_MODE"); envMode != "" {
		if envMode == "auth" || envMode == "rbac" {
			mode = envMode
		} else {
			fmt.Fprintf(os.Stderr, "Invalid PROXY_MODE environment variable: %s\n", envMode)
			fmt.Fprintf(os.Stderr, "PROXY_MODE must be 'auth' or 'rbac'\n")
			os.Exit(1)
		}
	}

	// Command line argument can override environment variable
	if len(args) > 0 {
		firstArg := args[0]
		if firstArg == "auth" || firstArg == "rbac" {
			mode = firstArg
			args = args[1:] // Remove mode from args
		} else if !strings.HasPrefix(firstArg, "-") {
			// If it doesn't start with a dash and isn't a valid mode, show error
			fmt.Fprintf(os.Stderr, "Invalid mode: %s\n", firstArg)
			fmt.Fprintf(os.Stderr, "Usage: %s [auth|rbac] [additional arguments...]\n", os.Args[0])
			fmt.Fprintf(os.Stderr, "Mode can also be set with PROXY_MODE environment variable\n")
			fmt.Fprintf(os.Stderr, "  auth - Run kube-auth-proxy\n")
			fmt.Fprintf(os.Stderr, "  rbac - Run kube-rbac-proxy (default)\n")
			os.Exit(1)
		}
	}

	var binary string
	switch mode {
	case "auth":
		fmt.Println("Starting kube-auth-proxy...")
		binary = "/bin/kube-auth-proxy"
	case "rbac":
		fmt.Println("Starting kube-rbac-proxy...")
		binary = "/bin/kube-rbac-proxy"
	default:
		fmt.Fprintf(os.Stderr, "Invalid mode: %s\n", mode)
		fmt.Fprintf(os.Stderr, "Usage: %s [auth|rbac] [additional arguments...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Mode can also be set with PROXY_MODE environment variable\n")
		fmt.Fprintf(os.Stderr, "  auth - Run kube-auth-proxy\n")
		fmt.Fprintf(os.Stderr, "  rbac - Run kube-rbac-proxy (default)\n")
		os.Exit(1)
	}

	// Execute the binary
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			// If the command exited with an error, exit with the same code
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		fmt.Fprintf(os.Stderr, "Error executing %s: %v\n", binary, err)
		os.Exit(1)
	}
}