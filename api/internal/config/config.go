package config

import (
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/zrpc"
)

type Config struct {
	rest.RestConf
	Auth struct {
		AccessSecret string
		AccessExpire int64
	}
	Mongo struct {
		Uri    string
		DbName string
	}
	Redis   redis.RedisConf
	TaskRpc zrpc.RpcClientConf
	// Worker安装配置
	WorkerInstall struct {
		ServerAddr string `json:",optional"` // API服务外部访问地址，如 192.168.1.100:8888
		RpcAddr    string `json:",optional"` // RPC服务外部访问地址，如 192.168.1.100:9000
	} `json:",optional"`
	// Worker控制台安全配置
	Console ConsoleConfig `json:",optional"`
}
