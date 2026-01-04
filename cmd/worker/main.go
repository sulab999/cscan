package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"cscan/worker"

	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/stat"
)

var (
	// 新参数：-s 改为 API 服务地址
	serverAddr  = flag.String("s", "http://localhost:8888", "API server address (e.g., http://192.168.1.100:8888)")
	workerName  = flag.String("n", "", "worker name (default: hostname-pid)")
	concurrency = flag.Int("c", 5, "concurrency")
	installKey  = flag.String("k", "", "install key for authentication")

	// 废弃参数（保留兼容性，但会输出警告）
	redisAddr = flag.String("r", "", "[DEPRECATED] redis address - no longer needed, will be ignored")
	redisPass = flag.String("rp", "", "[DEPRECATED] redis password - no longer needed, will be ignored")
	apiAddr   = flag.String("a", "", "[DEPRECATED] use -s instead for API server address")
)

// validateInstallKey 验证安装密钥
func validateInstallKey(apiServer, key, name string) error {
	reqBody := map[string]string{
		"installKey": key,
		"workerName": name,
		"workerIP":   worker.GetLocalIP(),
		"workerOS":   runtime.GOOS,
		"workerArch": runtime.GOARCH,
	}
	jsonData, _ := json.Marshal(reqBody)

	// 构建API地址
	url := fmt.Sprintf("%s/api/v1/worker/validate", apiServer)

	// 发送验证请求，带重试
	var lastErr error
	for i := 0; i < 3; i++ {
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = err
			fmt.Printf("[Worker] Validation attempt %d failed: %v, retrying...\n", i+1, err)
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var result struct {
			Code  int    `json:"code"`
			Msg   string `json:"msg"`
			Valid bool   `json:"valid"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			lastErr = fmt.Errorf("parse response failed: %v", err)
			continue
		}

		if result.Code != 0 || !result.Valid {
			return fmt.Errorf("validation failed: %s", result.Msg)
		}

		fmt.Printf("[Worker] Install key validated successfully\n")
		return nil
	}

	return fmt.Errorf("validation failed after 3 attempts: %v", lastErr)
}

func main() {
	flag.Parse()

	// 禁用统计日志
	stat.DisableLog()
	logx.DisableStat()

	// 检查废弃参数并输出警告
	if *redisAddr != "" {
		fmt.Println("[Worker] WARNING: -r (redis address) is deprecated and will be ignored. Worker now communicates through API only.")
	}
	if *redisPass != "" {
		fmt.Println("[Worker] WARNING: -rp (redis password) is deprecated and will be ignored.")
	}
	if *apiAddr != "" {
		fmt.Println("[Worker] WARNING: -a is deprecated, please use -s for API server address.")
		// 如果用户使用了旧的 -a 参数，将其值赋给 serverAddr
		if *serverAddr == "http://localhost:8888" {
			*serverAddr = *apiAddr
		}
	}

	// 生成Worker名称
	name := *workerName
	if name == "" {
		name = worker.GetWorkerName()
	}

	// 强制要求安装密钥
	if *installKey == "" {
		fmt.Println("[Worker] Error: install key is required (-k flag)")
		fmt.Println("[Worker] Please get the install key from the admin panel")
		os.Exit(1)
	}

	// 确定API服务器地址
	apiServer := *serverAddr
	// 确保地址有协议前缀
	if !strings.HasPrefix(apiServer, "http://") && !strings.HasPrefix(apiServer, "https://") {
		apiServer = "http://" + apiServer
	}

	fmt.Printf("[Worker] Using API server: %s\n", apiServer)
	fmt.Println("[Worker] Validating install key...")

	// 验证安装密钥
	if err := validateInstallKey(apiServer, *installKey, name); err != nil {
		fmt.Printf("[Worker] Authentication failed: %v\n", err)
		os.Exit(1)
	}

	// 获取本机IP
	ip := worker.GetLocalIP()

	config := worker.WorkerConfig{
		Name:        name,
		IP:          ip,
		ServerAddr:  apiServer, // 现在是 API 服务地址
		InstallKey:  *installKey,
		Concurrency: *concurrency,
		Timeout:     3600,
	}

	w, err := worker.NewWorker(config)
	if err != nil {
		logx.Errorf("create worker failed: %v", err)
		os.Exit(1)
	}

	// 启动Worker
	w.Start()

	fmt.Printf("Worker started:\n")
	fmt.Printf("  Name: %s\n", name)
	fmt.Printf("  IP: %s\n", ip)
	fmt.Printf("  API Server: %s\n", apiServer)
	fmt.Printf("  Concurrency: %d\n", *concurrency)

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("Shutting down worker...")
	w.Stop()
}
