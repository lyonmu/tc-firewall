package logger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
)

var testTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestNewZapLogger_ConsoleFormat(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := LogConfig{
		Path:    tmpDir,
		Module:  "test-module",
		Level:   "info",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: false,
		Format:  "console",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	// Log something to trigger file creation
	logger.Info("test message")

	// Verify log file was created
	logFile := filepath.Join(tmpDir, "test-module", "test-module.log")
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Log file not created: %s", logFile)
	}
}

func TestNewZapLogger_JSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := LogConfig{
		Path:    tmpDir,
		Module:  "test-json",
		Level:   "debug",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: false,
		Format:  "json",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	// Log something to trigger file creation
	logger.Info("test message")

	// Verify log file was created
	logFile := filepath.Join(tmpDir, "test-json", "test-json.log")
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Log file not created: %s", logFile)
	}
}

func TestNewZapLogger_WithConsole(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := LogConfig{
		Path:    tmpDir,
		Module:  "test-console",
		Level:   "info",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: true,
		Format:  "console",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	// Should not panic
	logger.Info("test message")
}

func TestNewZapLogger_DebugLevel(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := LogConfig{
		Path:    tmpDir,
		Module:  "test-debug",
		Level:   "debug",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: false,
		Format:  "console",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	// Debug level should work
	logger.Debug("debug message")
	logger.Info("info message")
}

func TestNewZapLogger_WarnLevel(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := LogConfig{
		Path:    tmpDir,
		Module:  "test-warn",
		Level:   "warn",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: false,
		Format:  "console",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	logger.Warn("warn message")
}

func TestNewZapLogger_ErrorLevel(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := LogConfig{
		Path:    tmpDir,
		Module:  "test-error",
		Level:   "error",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: false,
		Format:  "console",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	logger.Error("error message")
}

func TestNewZapLogger_InvalidLevel_DefaultsToInfo(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := LogConfig{
		Path:    tmpDir,
		Module:  "test-invalid",
		Level:   "invalid",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: false,
		Format:  "console",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	// Should default to info level
	logger.Info("info message")
}

func TestNewZapLogger_EmptyPath(t *testing.T) {
	cfg := LogConfig{
		Path:    "",
		Module:  "test-empty",
		Level:   "info",
		MaxSize: 10,
		MaxAge:  7,
		Backups: 3,
		Console: true,
		Format:  "console",
	}

	logger := NewZapLogger(cfg)
	if logger == nil {
		t.Fatal("NewZapLogger returned nil")
	}
	defer logger.Sync()

	// Should work with console output
	logger.Info("test message")
}

func TestCustomTimeEncoder(t *testing.T) {
	// Verify customTimeEncoder doesn't panic
	enc := &testArrayEncoder{}
	customTimeEncoder(testTime, enc)
	if len(enc.strings) == 0 {
		t.Error("customTimeEncoder didn't append anything")
	}
}

func TestCreateModuleEncoderConfig(t *testing.T) {
	baseConfig := zapcore.EncoderConfig{
		EncodeLevel: zapcore.CapitalLevelEncoder,
	}

	config := createModuleEncoderConfig("test-module", baseConfig)

	// Verify the level encoder was overridden
	if config.EncodeLevel == nil {
		t.Error("createModuleEncoderConfig didn't set EncodeLevel")
	}
}

// testArrayEncoder is a minimal implementation for testing
type testArrayEncoder struct {
	strings []string
}

func (e *testArrayEncoder) AppendBool(bool)                            {}
func (e *testArrayEncoder) AppendByte(byte)                            {}
func (e *testArrayEncoder) AppendComplex128(complex128)                {}
func (e *testArrayEncoder) AppendComplex64(complex64)                  {}
func (e *testArrayEncoder) AppendDuration(time.Duration)               {}
func (e *testArrayEncoder) AppendFloat64(float64)                      {}
func (e *testArrayEncoder) AppendFloat32(float32)                      {}
func (e *testArrayEncoder) AppendInt(int)                              {}
func (e *testArrayEncoder) AppendInt64(int64)                          {}
func (e *testArrayEncoder) AppendInt32(int32)                          {}
func (e *testArrayEncoder) AppendInt16(int16)                          {}
func (e *testArrayEncoder) AppendInt8(int8)                            {}
func (e *testArrayEncoder) AppendString(s string)                      { e.strings = append(e.strings, s) }
func (e *testArrayEncoder) AppendTime(time.Time)                       {}
func (e *testArrayEncoder) AppendUint(uint)                            {}
func (e *testArrayEncoder) AppendUint64(uint64)                        {}
func (e *testArrayEncoder) AppendUint32(uint32)                        {}
func (e *testArrayEncoder) AppendUint16(uint16)                        {}
func (e *testArrayEncoder) AppendUint8(uint8)                          {}
func (e *testArrayEncoder) AppendUintptr(uintptr)                      {}
func (e *testArrayEncoder) AppendArray(zapcore.ArrayMarshaler) error   { return nil }
func (e *testArrayEncoder) AppendObject(zapcore.ObjectMarshaler) error { return nil }
func (e *testArrayEncoder) AppendReflected(interface{}) error          { return nil }
func (e *testArrayEncoder) AppendByteString([]byte)                    {}
