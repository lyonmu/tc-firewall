package global

import (
	"github.com/lyonmu/tc-firewall/internal/config"
	"go.uber.org/zap"
)

var (
	Cfg    *config.Config
	Logger *zap.Logger
)
