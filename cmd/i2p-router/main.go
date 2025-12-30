// Package main implements the I2P router daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-i2p/go-i2p/pkg/debug"
	"github.com/go-i2p/go-i2p/pkg/router"
)

var (
	version = "0.1.0"
)

func main() {
	// Parse command-line flags
	dataDir := flag.String("data", defaultDataDir(), "Data directory")
	ntcp2Addr := flag.String("ntcp2", "0.0.0.0:9001", "NTCP2 listen address")
	ssu2Addr := flag.String("ssu2", "0.0.0.0:9001", "SSU2 listen address")
	floodfill := flag.Bool("floodfill", false, "Enable floodfill mode")
	bandwidthIn := flag.Int("bw-in", 256, "Inbound bandwidth limit (KB/s)")
	bandwidthOut := flag.Int("bw-out", 256, "Outbound bandwidth limit (KB/s)")

	// Debug/trace flags
	logLevel := flag.String("log", "info", "Log level (off, error, warn, info, debug, trace)")
	logFile := flag.String("log-file", "", "Log to file instead of stderr")
	logSubs := flag.String("log-subsystems", "", "Comma-separated list of subsystems to trace (router,ntcp2,ssu2,tunnel,netdb,garlic,stream,sam,proxy,irc,eepsite,crypto)")
	showStack := flag.Bool("log-stack", false, "Show stack traces for debug/trace messages")
	noColor := flag.Bool("no-color", false, "Disable colored log output")
	showStats := flag.Bool("stats", false, "Show periodic statistics")
	statsInterval := flag.Int("stats-interval", 30, "Statistics display interval in seconds")

	flag.Parse()

	// Configure debug/trace system
	debugConfig := &debug.Config{
		Level:      debug.ParseLevel(*logLevel),
		Output:     "stderr",
		UseColors:  !*noColor,
		ShowTime:   true,
		ShowCaller: true,
		ShowStack:  *showStack,
	}

	if *logFile != "" {
		debugConfig.Output = *logFile
	}

	// Parse subsystems
	if *logSubs != "" {
		subs := strings.Split(*logSubs, ",")
		for _, s := range subs {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "router":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubRouter)
			case "ntcp2":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubNTCP2)
			case "ssu2":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubSSU2)
			case "tunnel":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubTunnel)
			case "netdb":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubNetDB)
			case "garlic":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubGarlic)
			case "stream":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubStreaming)
			case "sam":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubSAM)
			case "proxy":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubProxy)
			case "irc":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubIRC)
			case "eepsite":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubEepsite)
			case "crypto":
				debugConfig.Subsystems = append(debugConfig.Subsystems, debug.SubCrypto)
			}
		}
	}

	if err := debug.Configure(debugConfig); err != nil {
		log.Fatalf("Failed to configure logging: %v", err)
	}
	defer debug.Close()

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
	fmt.Printf("  Version %s\n", version)
	fmt.Println("===========================================")
	fmt.Println()

	fmt.Printf("Data directory: %s\n", config.DataDir)
	fmt.Printf("NTCP2 address:  %s\n", config.NTCP2Addr)
	fmt.Printf("SSU2 address:   %s\n", config.SSU2Addr)
	fmt.Printf("Floodfill:      %v\n", config.Floodfill)
	fmt.Printf("Log level:      %s\n", debugConfig.Level)
	if *logFile != "" {
		fmt.Printf("Log file:       %s\n", *logFile)
	}
	fmt.Println()

	// Create router
	debug.Info(debug.SubRouter, "creating router with data dir: %s", config.DataDir)
	r, err := router.New(config)
	if err != nil {
		log.Fatalf("Failed to create router: %v", err)
	}

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

	// Start stats display if enabled
	if *showStats {
		go displayStats(r, *statsInterval, sigChan)
	}

	fmt.Println("Press Ctrl+C to stop...")
	fmt.Println()

	// Wait for shutdown signal
	<-sigChan
	fmt.Println()
	fmt.Println("Shutting down...")

	r.Stop()
	fmt.Println("Router stopped")
}

// displayStats displays router statistics periodically.
func displayStats(r *router.Router, interval int, done chan os.Signal) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			stats := r.Stats()
			fmt.Println()
			fmt.Println("=== Router Statistics ===")
			fmt.Printf("  RouterInfos:     %d\n", stats.RouterInfos)
			fmt.Printf("  LeaseSets:       %d\n", stats.LeaseSets)
			fmt.Printf("  Floodfills:      %d\n", stats.Floodfills)
			fmt.Printf("  NTCP2 Sessions:  %d\n", stats.NTCP2Sessions)
			fmt.Printf("  SSU2 Sessions:   %d\n", stats.SSU2Sessions)
			fmt.Printf("  Inbound Tunnels: %d\n", stats.InboundTunnels)
			fmt.Printf("  Outbound Tunnels: %d\n", stats.OutboundTunnels)
			fmt.Printf("  Transit Tunnels: %d\n", stats.TransitTunnels)
			fmt.Println("=========================")
		}
	}
}

// defaultDataDir returns the default data directory.
func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".i2p-go"
	}
	return filepath.Join(home, ".i2p-go")
}
