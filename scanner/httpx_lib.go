package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/httpx/runner"
	"github.com/zeromicro/go-zero/core/logx"
)

// HttpxLibScanner 使用httpx库进行HTTP探测
type HttpxLibScanner struct {
	mu sync.Mutex
}

// NewHttpxLibScanner 创建httpx库扫描器
func NewHttpxLibScanner() *HttpxLibScanner {
	return &HttpxLibScanner{}
}

// HttpxLibResult httpx库扫描结果
type HttpxLibResult struct {
	URL          string
	Host         string
	Port         int
	Title        string
	StatusCode   int
	Technologies []string
	FaviconHash  string
	Server       string
	ContentType  string
	Body         string
	Headers      string
	Screenshot   string
	Scheme       string
}

// RunHttpxLib 使用httpx库进行批量HTTP探测
func (s *FingerprintScanner) RunHttpxLib(ctx context.Context, assets []*Asset, opts *FingerprintOptions) error {
	if len(assets) == 0 {
		return nil
	}

	// 构建目标列表
	var targets []string
	targetMap := make(map[string]*Asset)
	for _, asset := range assets {
		target := fmt.Sprintf("%s:%d", asset.Host, asset.Port)
		targets = append(targets, target)
		targetMap[target] = asset
		// 同时添加带协议的目标，提高匹配率
		targetMap[fmt.Sprintf("http://%s:%d", asset.Host, asset.Port)] = asset
		targetMap[fmt.Sprintf("https://%s:%d", asset.Host, asset.Port)] = asset
	}

	// 结果处理锁
	var mu sync.Mutex

	// 配置httpx选项
	httpxOpts := runner.Options{
		Methods:               "GET",
		InputTargetHost:       targets,
		StatusCode:            true,
		ExtractTitle:          true,
		TechDetect:            true,
		Favicon:               true,
		FollowRedirects:       true,
		MaxRedirects:          5,
		Threads:               opts.Concurrency,
		Timeout:               opts.TargetTimeout,
		NoFallback:            false,
		NoFallbackScheme:      false,
		OutputServerHeader:    true,
		OutputContentType:     true,
		ResponseInStdout:      true,
		Silent:                true,
		DisableUpdateCheck:    true,
		RandomAgent:           true,
		TLSGrab:               false,
		OutputIP:              true,
		LeaveDefaultPorts:     false,
		HostMaxErrors:         30,
		// 设置结果回调
		OnResult: func(result runner.Result) {
			mu.Lock()
			defer mu.Unlock()

			// 检查错误
			if result.Err != nil {
				logx.Debugf("httpx error for %s: %v", result.Input, result.Err)
				return
			}

			// 匹配资产
			var asset *Asset
			var key string

			// 尝试从Input匹配
			if result.Input != "" {
				key = result.Input
				asset = targetMap[key]
			}

			// 如果Input匹配失败，尝试从URL解析
			if asset == nil && result.URL != "" {
				if u, err := url.Parse(result.URL); err == nil {
					host := u.Hostname()
					port := u.Port()
					if port == "" {
						if u.Scheme == "https" {
							port = "443"
						} else {
							port = "80"
						}
					}
					key = fmt.Sprintf("%s:%s", host, port)
					asset = targetMap[key]

					// 还是没找到，尝试完整URL匹配
					if asset == nil {
						asset = targetMap[result.URL]
					}
				}
			}

			if asset == nil {
				logx.Debugf("httpx result not matched: input=%s, url=%s", result.Input, result.URL)
				return
			}

			// 更新资产信息
			asset.Title = result.Title
			asset.HttpStatus = fmt.Sprintf("%d", result.StatusCode)

			// 从URL或Scheme字段获取协议
			if result.Scheme != "" {
				asset.Service = result.Scheme
			} else if u, err := url.Parse(result.URL); err == nil {
				asset.Service = u.Scheme
			}

			// 技术检测结果
			if len(result.Technologies) > 0 {
				for _, tech := range result.Technologies {
					asset.App = append(asset.App, tech+"[httpx]")
				}
			}

			// Favicon hash
			if result.FavIconMMH3 != "" {
				asset.IconHash = result.FavIconMMH3
			}

			// Server header
			if result.WebServer != "" {
				asset.Server = result.WebServer
			}

			// Response headers
			if result.RawHeaders != "" {
				asset.HttpHeader = result.RawHeaders
			} else if result.ResponseHeaders != nil {
				var headerBuilder strings.Builder
				// 添加状态行
				headerBuilder.WriteString(fmt.Sprintf("HTTP/1.1 %d\n", result.StatusCode))
				for k, v := range result.ResponseHeaders {
					headerBuilder.WriteString(fmt.Sprintf("%s: %v\n", k, v))
				}
				asset.HttpHeader = headerBuilder.String()
			}

			// Response body
			if result.ResponseBody != "" {
				body := result.ResponseBody
				// 限制body大小
				if len(body) > 50*1024 {
					body = body[:50*1024] + "\n...[truncated]"
				}
				asset.HttpBody = body
			}

			// Screenshot (base64)
			if len(result.ScreenshotBytes) > 0 {
				asset.Screenshot = base64.StdEncoding.EncodeToString(result.ScreenshotBytes)
			}

			logx.Debugf("httpx lib matched: %s -> title=%s, status=%d, techs=%v",
				key, result.Title, result.StatusCode, result.Technologies)
		},
	}

	// 如果需要截图
	if opts.Screenshot {
		httpxOpts.Screenshot = true
		httpxOpts.UseInstalledChrome = true
	}

	// 创建httpx runner
	httpxRunner, err := runner.New(&httpxOpts)
	if err != nil {
		logx.Errorf("Failed to create httpx runner: %v", err)
		return err
	}
	defer httpxRunner.Close()

	// 运行扫描
	logx.Infof("Running httpx library scan for %d targets", len(targets))
	httpxRunner.RunEnumeration()

	return nil
}

// runHttpxLib 使用httpx库进行批量探测（替代原有的runHttpx命令行方式）
func (s *FingerprintScanner) runHttpxLib(ctx context.Context, assets []*Asset, opts *FingerprintOptions) {
	if err := s.RunHttpxLib(ctx, assets, opts); err != nil {
		logx.Errorf("httpx library scan failed: %v", err)
	}
}
