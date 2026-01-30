package pkg

import (
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/lyonmu/tc-firewall/internal/global"
	"github.com/spf13/viper"
)

// ConfigManager 是一个泛型配置管理器，支持类型安全的配置热重载
type ConfigManager[T any] struct {
	mu      sync.RWMutex  // 读写锁，保护配置数据
	v       *viper.Viper  // viper实例
	cfg     T             // 当前配置，泛型类型
	exit    chan struct{} // 用于优雅关闭监听
	watchCh chan struct{} // 用于通知配置变更
}

// NewConfigManager 创建一个新的泛型配置管理器
func NewConfigManager[T any]() *ConfigManager[T] {
	return &ConfigManager[T]{
		v:       viper.New(),
		exit:    make(chan struct{}),
		watchCh: make(chan struct{}, 1), // 带缓冲的通道，防止阻塞
	}
}

// LoadConfig 从指定路径加载配置文件并启用热重载
// path: 配置文件路径
// filetype: 配置文件类型，如"yaml"、"json"、"toml"等
func (cm *ConfigManager[T]) LoadConfig(path string, filetype string) error {
	cm.v.SetConfigFile(path)
	cm.v.SetConfigType(filetype)

	// 读取配置文件
	if err := cm.v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// 创建配置实例
	var cfg T
	if err := cm.v.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 保存配置
	cm.mu.Lock()
	cm.cfg = cfg
	cm.mu.Unlock()

	// 启动热重载监听
	go cm.watchConfig()

	return nil
}

// watchConfig 监听配置文件变化
func (cm *ConfigManager[T]) watchConfig() {
	// Helper to get logger safely
	log := global.GetLogger()

	// 设置配置变更回调
	cm.v.OnConfigChange(func(e fsnotify.Event) {
		cm.mu.Lock()
		defer cm.mu.Unlock()

		if log != nil {
			log.Sugar().Infof("Config file updated: %s", e.Name)
		} else {
			fmt.Printf("Config file updated: %s\n", e.Name)
		}

		var newCfg T
		// 重新读取配置
		if err := cm.v.ReadInConfig(); err != nil {
			if log != nil {
				log.Sugar().Errorf("Failed to read updated config: %v", err)
			} else {
				fmt.Fprintf(os.Stderr, "Failed to read updated config: %v\n", err)
			}
			return
		}

		// 解析到新配置
		if err := cm.v.Unmarshal(&newCfg); err != nil {
			if log != nil {
				log.Sugar().Errorf("Failed to unmarshal updated config: %v", err)
			} else {
				fmt.Fprintf(os.Stderr, "Failed to unmarshal updated config: %v\n", err)
			}
			return
		}

		// 更新配置
		cm.cfg = newCfg
		if log != nil {
			log.Sugar().Info("Config successfully reloaded")
		} else {
			fmt.Println("Config successfully reloaded")
		}

		// 通知监听者配置已变更
		select {
		case cm.watchCh <- struct{}{}:
		default:
			// 通道已满，丢弃通知（避免阻塞）
		}
	})

	// 启动监听
	cm.v.WatchConfig()

	// 等待退出信号
	<-cm.exit
}

// GetConfig 获取当前配置的副本，线程安全
func (cm *ConfigManager[T]) GetConfig() T {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 返回配置的副本，防止外部修改
	cfg := cm.cfg
	return cfg
}

// GetConfigPtr 获取当前配置的指针，适用于大配置结构避免复制
// 注意：调用者不应修改返回的配置
func (cm *ConfigManager[T]) GetConfigPtr() *T {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return &cm.cfg
}

// Watch 返回一个通道，用于监听配置变更事件
func (cm *ConfigManager[T]) Watch() <-chan struct{} {
	return cm.watchCh
}

// Close 停止监听配置变化
func (cm *ConfigManager[T]) Close() {
	close(cm.exit)
	// 清空watchCh，防止内存泄漏
	go func() {
		for range cm.watchCh {
		}
	}()
}
