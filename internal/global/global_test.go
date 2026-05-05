package global

import (
	"runtime"
	"sync"
	"testing"

	"github.com/lyonmu/tc-firewall/internal/config"
	"go.uber.org/zap"
)

func TestGetCfg_ReturnsNilWhenNotSet(t *testing.T) {
	// Reset global state
	cfgMu.Lock()
	Cfg = nil
	cfgMu.Unlock()

	got := GetCfg()
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestGetLogger_ReturnsNilWhenNotSet(t *testing.T) {
	// Reset global state
	loggerMu.Lock()
	Logger = nil
	loggerMu.Unlock()

	got := GetLogger()
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestSetCfg_GetCfg_Roundtrip(t *testing.T) {
	// Reset global state
	cfgMu.Lock()
	Cfg = nil
	cfgMu.Unlock()

	want := &config.Config{
		Interface:  "eth0",
		ConfigPath: "/tmp/config.json",
		ConfigType: "json",
		Version:    true,
	}

	SetCfg(want)
	got := GetCfg()

	if got != want {
		t.Errorf("expected %+v, got %+v", want, got)
	}
	if got.Interface != want.Interface {
		t.Errorf("Interface: expected %q, got %q", want.Interface, got.Interface)
	}
}

func TestSetLogger_GetLogger_Roundtrip(t *testing.T) {
	// Reset global state
	loggerMu.Lock()
	Logger = nil
	loggerMu.Unlock()

	want, _ := zap.NewDevelopment()
	defer want.Sync()

	SetLogger(want)
	got := GetLogger()

	if got != want {
		t.Errorf("expected %+v, got %+v", want, got)
	}
}

func TestSetCfg_GetCfg_Concurrent(t *testing.T) {
	// Reset global state
	cfgMu.Lock()
	Cfg = nil
	cfgMu.Unlock()

	runtime.GOMAXPROCS(runtime.NumCPU())

	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // readers + writers

	// Launch writer goroutines
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				cfg := &config.Config{
					Interface:  "eth0",
					ConfigPath: "/tmp/config.json",
					ConfigType: "json",
					Version:    id%2 == 0,
				}
				SetCfg(cfg)
			}
		}(i)
	}

	// Launch reader goroutines
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = GetCfg()
			}
		}()
	}

	wg.Wait()
}

func TestSetLogger_GetLogger_Concurrent(t *testing.T) {
	// Reset global state
	loggerMu.Lock()
	Logger = nil
	loggerMu.Unlock()

	runtime.GOMAXPROCS(runtime.NumCPU())

	const goroutines = 100
	const iterations = 1000

	// Pre-create loggers to avoid sync issues during test
	loggers := make([]*zap.Logger, goroutines)
	for i := 0; i < goroutines; i++ {
		loggers[i] = zap.NewNop().Named("test")
	}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // readers + writers

	// Launch writer goroutines
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				SetLogger(loggers[id%goroutines])
			}
		}(i)
	}

	// Launch reader goroutines
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = GetLogger()
			}
		}()
	}

	wg.Wait()
}
