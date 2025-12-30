// Package debug provides configurable tracing and debugging utilities for the I2P router.
package debug

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level represents the logging level.
type Level int32

const (
	LevelOff Level = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

func (l Level) String() string {
	switch l {
	case LevelOff:
		return "OFF"
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	case LevelTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a level string.
func ParseLevel(s string) Level {
	switch strings.ToUpper(s) {
	case "OFF", "NONE":
		return LevelOff
	case "ERROR", "ERR":
		return LevelError
	case "WARN", "WARNING":
		return LevelWarn
	case "INFO":
		return LevelInfo
	case "DEBUG":
		return LevelDebug
	case "TRACE", "ALL":
		return LevelTrace
	default:
		return LevelInfo
	}
}

// Subsystem represents a component of the router.
type Subsystem string

const (
	SubRouter    Subsystem = "ROUTER"
	SubNTCP2     Subsystem = "NTCP2"
	SubSSU2      Subsystem = "SSU2"
	SubTunnel    Subsystem = "TUNNEL"
	SubNetDB     Subsystem = "NETDB"
	SubGarlic    Subsystem = "GARLIC"
	SubStreaming Subsystem = "STREAM"
	SubSAM       Subsystem = "SAM"
	SubProxy     Subsystem = "PROXY"
	SubIRC       Subsystem = "IRC"
	SubEepsite   Subsystem = "EEPSITE"
	SubCrypto    Subsystem = "CRYPTO"
	SubGeneral   Subsystem = "GENERAL"
)

// Tracer is the main tracing component.
type Tracer struct {
	mu sync.RWMutex

	level        atomic.Int32
	output       io.Writer
	file         *os.File
	useColors    bool
	showTime     bool
	showCaller   bool
	showStack    bool
	subsystems   map[Subsystem]bool
	allSubsystems bool
}

// Global tracer instance
var globalTracer = &Tracer{
	output:        os.Stderr,
	useColors:     true,
	showTime:      true,
	showCaller:    true,
	showStack:     false,
	subsystems:    make(map[Subsystem]bool),
	allSubsystems: true,
}

func init() {
	globalTracer.level.Store(int32(LevelInfo))
}

// Config holds tracer configuration.
type Config struct {
	Level         Level
	Output        string // "stderr", "stdout", or file path
	UseColors     bool
	ShowTime      bool
	ShowCaller    bool
	ShowStack     bool
	Subsystems    []Subsystem // Empty means all
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Level:      LevelInfo,
		Output:     "stderr",
		UseColors:  true,
		ShowTime:   true,
		ShowCaller: true,
		ShowStack:  false,
		Subsystems: nil,
	}
}

// Configure configures the global tracer.
func Configure(cfg *Config) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	globalTracer.mu.Lock()
	defer globalTracer.mu.Unlock()

	globalTracer.level.Store(int32(cfg.Level))
	globalTracer.useColors = cfg.UseColors
	globalTracer.showTime = cfg.ShowTime
	globalTracer.showCaller = cfg.ShowCaller
	globalTracer.showStack = cfg.ShowStack

	// Set output
	if globalTracer.file != nil {
		globalTracer.file.Close()
		globalTracer.file = nil
	}

	switch cfg.Output {
	case "stderr", "":
		globalTracer.output = os.Stderr
	case "stdout":
		globalTracer.output = os.Stdout
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		globalTracer.file = f
		globalTracer.output = f
		globalTracer.useColors = false // No colors for files
	}

	// Set subsystems
	globalTracer.subsystems = make(map[Subsystem]bool)
	if len(cfg.Subsystems) == 0 {
		globalTracer.allSubsystems = true
	} else {
		globalTracer.allSubsystems = false
		for _, sub := range cfg.Subsystems {
			globalTracer.subsystems[sub] = true
		}
	}

	return nil
}

// SetLevel sets the global log level.
func SetLevel(level Level) {
	globalTracer.level.Store(int32(level))
}

// GetLevel returns the current log level.
func GetLevel() Level {
	return Level(globalTracer.level.Load())
}

// EnableSubsystem enables tracing for a specific subsystem.
func EnableSubsystem(sub Subsystem) {
	globalTracer.mu.Lock()
	defer globalTracer.mu.Unlock()
	globalTracer.subsystems[sub] = true
	globalTracer.allSubsystems = false
}

// DisableSubsystem disables tracing for a specific subsystem.
func DisableSubsystem(sub Subsystem) {
	globalTracer.mu.Lock()
	defer globalTracer.mu.Unlock()
	delete(globalTracer.subsystems, sub)
}

// EnableAllSubsystems enables tracing for all subsystems.
func EnableAllSubsystems() {
	globalTracer.mu.Lock()
	defer globalTracer.mu.Unlock()
	globalTracer.allSubsystems = true
}

// EnableStackTraces enables stack traces on all log messages.
func EnableStackTraces() {
	globalTracer.mu.Lock()
	defer globalTracer.mu.Unlock()
	globalTracer.showStack = true
}

// DisableStackTraces disables stack traces.
func DisableStackTraces() {
	globalTracer.mu.Lock()
	defer globalTracer.mu.Unlock()
	globalTracer.showStack = false
}

// isEnabled checks if logging is enabled for the given level and subsystem.
func isEnabled(level Level, sub Subsystem) bool {
	if Level(globalTracer.level.Load()) < level {
		return false
	}

	globalTracer.mu.RLock()
	defer globalTracer.mu.RUnlock()

	if globalTracer.allSubsystems {
		return true
	}

	return globalTracer.subsystems[sub]
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[37m"
	colorBold   = "\033[1m"
)

func levelColor(level Level) string {
	switch level {
	case LevelError:
		return colorRed
	case LevelWarn:
		return colorYellow
	case LevelInfo:
		return colorGreen
	case LevelDebug:
		return colorBlue
	case LevelTrace:
		return colorGray
	default:
		return colorReset
	}
}

func log(level Level, sub Subsystem, format string, args ...interface{}) {
	if !isEnabled(level, sub) {
		return
	}

	globalTracer.mu.RLock()
	output := globalTracer.output
	useColors := globalTracer.useColors
	showTime := globalTracer.showTime
	showCaller := globalTracer.showCaller
	showStack := globalTracer.showStack
	globalTracer.mu.RUnlock()

	var buf strings.Builder

	// Time
	if showTime {
		buf.WriteString(time.Now().Format("2006-01-02 15:04:05.000"))
		buf.WriteString(" ")
	}

	// Level
	if useColors {
		buf.WriteString(levelColor(level))
		buf.WriteString(colorBold)
	}
	buf.WriteString(fmt.Sprintf("%-5s", level.String()))
	if useColors {
		buf.WriteString(colorReset)
	}
	buf.WriteString(" ")

	// Subsystem
	if useColors {
		buf.WriteString(colorCyan)
	}
	buf.WriteString(fmt.Sprintf("[%-8s]", sub))
	if useColors {
		buf.WriteString(colorReset)
	}
	buf.WriteString(" ")

	// Caller
	if showCaller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			file = filepath.Base(file)
			if useColors {
				buf.WriteString(colorPurple)
			}
			buf.WriteString(fmt.Sprintf("%s:%d", file, line))
			if useColors {
				buf.WriteString(colorReset)
			}
			buf.WriteString(" ")
		}
	}

	// Message
	buf.WriteString(fmt.Sprintf(format, args...))
	buf.WriteString("\n")

	// Stack trace
	if showStack && level <= LevelDebug {
		buf.WriteString(getStackTrace(3))
	}

	fmt.Fprint(output, buf.String())
}

// getStackTrace returns a formatted stack trace.
func getStackTrace(skip int) string {
	var buf strings.Builder
	buf.WriteString("  Stack trace:\n")

	pcs := make([]uintptr, 32)
	n := runtime.Callers(skip, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	for {
		frame, more := frames.Next()
		if strings.Contains(frame.Function, "runtime.") {
			if !more {
				break
			}
			continue
		}
		buf.WriteString(fmt.Sprintf("    %s\n        %s:%d\n",
			frame.Function, frame.File, frame.Line))
		if !more {
			break
		}
	}

	return buf.String()
}

// GetStackTrace returns the current stack trace as a string.
func GetStackTrace() string {
	return getStackTrace(2)
}

// Error logs an error message.
func Error(sub Subsystem, format string, args ...interface{}) {
	log(LevelError, sub, format, args...)
}

// Warn logs a warning message.
func Warn(sub Subsystem, format string, args ...interface{}) {
	log(LevelWarn, sub, format, args...)
}

// Info logs an info message.
func Info(sub Subsystem, format string, args ...interface{}) {
	log(LevelInfo, sub, format, args...)
}

// Debug logs a debug message.
func Debug(sub Subsystem, format string, args ...interface{}) {
	log(LevelDebug, sub, format, args...)
}

// Trace logs a trace message.
func Trace(sub Subsystem, format string, args ...interface{}) {
	log(LevelTrace, sub, format, args...)
}

// ErrorErr logs an error with the error value.
func ErrorErr(sub Subsystem, err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log(LevelError, sub, "%s: %v", msg, err)
}

// FuncEntry logs function entry (for trace level).
func FuncEntry(sub Subsystem) func() {
	if !isEnabled(LevelTrace, sub) {
		return func() {}
	}

	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		return func() {}
	}

	fn := runtime.FuncForPC(pc)
	funcName := "unknown"
	if fn != nil {
		funcName = filepath.Base(fn.Name())
	}
	file = filepath.Base(file)

	start := time.Now()
	log(LevelTrace, sub, "ENTER %s (%s:%d)", funcName, file, line)

	return func() {
		elapsed := time.Since(start)
		log(LevelTrace, sub, "EXIT  %s (%s:%d) [%v]", funcName, file, line, elapsed)
	}
}

// HexDump returns a hex dump of data (for debugging binary protocols).
func HexDump(data []byte, maxLen int) string {
	if len(data) == 0 {
		return "<empty>"
	}

	if maxLen > 0 && len(data) > maxLen {
		data = data[:maxLen]
	}

	var buf strings.Builder
	for i := 0; i < len(data); i += 16 {
		// Offset
		buf.WriteString(fmt.Sprintf("%04x  ", i))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				buf.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				buf.WriteString("   ")
			}
			if j == 7 {
				buf.WriteString(" ")
			}
		}

		// ASCII
		buf.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b < 127 {
				buf.WriteByte(b)
			} else {
				buf.WriteByte('.')
			}
		}
		buf.WriteString("|\n")
	}

	return buf.String()
}

// TraceData logs data with hex dump at trace level.
func TraceData(sub Subsystem, label string, data []byte) {
	if !isEnabled(LevelTrace, sub) {
		return
	}
	log(LevelTrace, sub, "%s (%d bytes):\n%s", label, len(data), HexDump(data, 256))
}

// DebugData logs data with hex dump at debug level.
func DebugData(sub Subsystem, label string, data []byte) {
	if !isEnabled(LevelDebug, sub) {
		return
	}
	log(LevelDebug, sub, "%s (%d bytes):\n%s", label, len(data), HexDump(data, 128))
}

// Close closes the tracer and any open files.
func Close() error {
	globalTracer.mu.Lock()
	defer globalTracer.mu.Unlock()

	if globalTracer.file != nil {
		err := globalTracer.file.Close()
		globalTracer.file = nil
		globalTracer.output = os.Stderr
		return err
	}
	return nil
}

// Logger provides a subsystem-specific logger.
type Logger struct {
	sub Subsystem
}

// NewLogger creates a new logger for a subsystem.
func NewLogger(sub Subsystem) *Logger {
	return &Logger{sub: sub}
}

func (l *Logger) Error(format string, args ...interface{}) {
	log(LevelError, l.sub, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	log(LevelWarn, l.sub, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	log(LevelInfo, l.sub, format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	log(LevelDebug, l.sub, format, args...)
}

func (l *Logger) Trace(format string, args ...interface{}) {
	log(LevelTrace, l.sub, format, args...)
}

func (l *Logger) FuncEntry() func() {
	if !isEnabled(LevelTrace, l.sub) {
		return func() {}
	}

	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		return func() {}
	}

	fn := runtime.FuncForPC(pc)
	funcName := "unknown"
	if fn != nil {
		funcName = filepath.Base(fn.Name())
	}
	file = filepath.Base(file)

	start := time.Now()
	log(LevelTrace, l.sub, "ENTER %s (%s:%d)", funcName, file, line)

	return func() {
		elapsed := time.Since(start)
		log(LevelTrace, l.sub, "EXIT  %s (%s:%d) [%v]", funcName, file, line, elapsed)
	}
}

func (l *Logger) TraceData(label string, data []byte) {
	TraceData(l.sub, label, data)
}

func (l *Logger) DebugData(label string, data []byte) {
	DebugData(l.sub, label, data)
}

func (l *Logger) IsEnabled(level Level) bool {
	return isEnabled(level, l.sub)
}
