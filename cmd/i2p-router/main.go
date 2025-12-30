// Package main implements the I2P router daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/go-i2p/go-i2p/pkg/router"
)

func main() {
	// Parse command-line flags
	dataDir := flag.String("data", defaultDataDir(), "Data directory")
	ntcp2Addr := flag.String("ntcp2", "0.0.0.0:9001", "NTCP2 listen address")
	ssu2Addr := flag.String("ssu2", "0.0.0.0:9001", "SSU2 listen address")
	floodfill := flag.Bool("floodfill", false, "Enable floodfill mode")
	bandwidthIn := flag.Int("bw-in", 256, "Inbound bandwidth limit (KB/s)")
	bandwidthOut := flag.Int("bw-out", 256, "Outbound bandwidth limit (KB/s)")
	logLevel := flag.String("log", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	// Create config
	config := &router.Config{
		DataDir:              *dataDir,
		NTCP2Addr:            *ntcp2Addr,
		SSU2Addr:             *ssu2Addr,
		Floodfill:            *floodfill,
		BandwidthIn:          *bandwidthIn,
		BandwidthOut:         *bandwidthOut,
		BandwidthShare:       80,
		IdentityPath:         "router.keys.dat",
		InboundTunnelLength:  3,
		OutboundTunnelLength: 3,
		InboundTunnelCount:   2,
		OutboundTunnelCount:  2,
		LogLevel:             *logLevel,
	}

	// Print banner
	fmt.Println("===========================================")
	fmt.Println("  I2P Router (Go Implementation)")
	fmt.Println("  Version 0.1.0")
	fmt.Println("===========================================")
	fmt.Println()

	// Create router
	r, err := router.New(config)
	if err != nil {
		log.Fatalf("Failed to create router: %v", err)
	}

	fmt.Printf("Data directory: %s\n", config.DataDir)
	fmt.Printf("NTCP2 address: %s\n", config.NTCP2Addr)
	fmt.Printf("SSU2 address: %s\n", config.SSU2Addr)
	fmt.Printf("Floodfill: %v\n", config.Floodfill)
	fmt.Println()

	// Start router
	fmt.Println("Starting router...")
	if err := r.Start(); err != nil {
		log.Fatalf("Failed to start router: %v", err)
	}
	fmt.Println("Router started successfully")
	fmt.Println()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Print status periodically
	go func() {
		for {
			select {
			case <-sigChan:
				return
			default:
			}
		}
	}()

	fmt.Println("Press Ctrl+C to stop...")
	fmt.Println()

	// Wait for shutdown signal
	<-sigChan
	fmt.Println()
	fmt.Println("Shutting down...")

	r.Stop()
	fmt.Println("Router stopped")
}

// defaultDataDir returns the default data directory.
func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".i2p-go"
	}
	return filepath.Join(home, ".i2p-go")
}
