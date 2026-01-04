package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/core/logx"
)

// WorkerNameKey Context key for worker name
const WorkerNameKey ContextKey = "workerName"

// WorkerAuthMiddleware Worker认证中间件
type WorkerAuthMiddleware struct {
	RedisClient *redis.Client
}

// NewWorkerAuthMiddleware 创建Worker认证中间件
func NewWorkerAuthMiddleware(redisClient *redis.Client) *WorkerAuthMiddleware {
	return &WorkerAuthMiddleware{
		RedisClient: redisClient,
	}
}

// Handle Worker认证处理
func (m *WorkerAuthMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 从请求头获取Install Key
		installKey := r.Header.Get("X-Worker-Key")
		if installKey == "" {
			workerUnauthorized(w, "未提供Worker认证密钥")
			logx.Errorf("[WorkerAuth] Missing X-Worker-Key header from %s", r.RemoteAddr)
			return
		}

		// 从Redis获取存储的Install Key
		installKeyKey := "cscan:worker:install_key"
		storedKey, err := m.RedisClient.Get(r.Context(), installKeyKey).Result()
		if err != nil || storedKey == "" {
			workerUnauthorized(w, "服务端未配置安装密钥")
			logx.Errorf("[WorkerAuth] Install key not configured in Redis")
			return
		}

		// 验证Install Key
		if installKey != storedKey {
			workerUnauthorized(w, "Worker认证密钥无效")
			logx.Errorf("[WorkerAuth] Invalid install key attempt: %s from %s", installKey, r.RemoteAddr)
			return
		}

		// 可选：从请求头获取Worker名称并存入Context
		workerName := r.Header.Get("X-Worker-Name")
		if workerName != "" {
			ctx := context.WithValue(r.Context(), WorkerNameKey, workerName)
			r = r.WithContext(ctx)
		}

		next(w, r)
	}
}

// workerUnauthorized 返回401未授权响应
func workerUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 401,
		"msg":  msg,
	})
}

// GetWorkerName 从Context获取Worker名称
func GetWorkerName(ctx context.Context) string {
	if v := ctx.Value(WorkerNameKey); v != nil {
		return v.(string)
	}
	return ""
}
