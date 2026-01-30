package global

import (
	"sync"

	"github.com/lyonmu/tc-firewall/internal/config"
	"go.uber.org/zap"
)

var (
	cfgMu sync.RWMutex
	Cfg   *config.Config

	loggerMu sync.RWMutex
	Logger   *zap.Logger
)

// SetCfg sets the global config (thread-safe)
func SetCfg(cfg *config.Config) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	Cfg = cfg
}

// GetCfg gets the global config (thread-safe)
func GetCfg() *config.Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return Cfg
}

// SetLogger sets the global logger (thread-safe)
func SetLogger(l *zap.Logger) {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	Logger = l
}

// GetLogger gets the global logger (thread-safe)
func GetLogger() *zap.Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return Logger
}
