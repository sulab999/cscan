package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WorkerHTTPClient Worker HTTP 客户端
// 用于替代原有 RPC 客户端，通过 HTTP 调用 API 接口
type WorkerHTTPClient struct {
	baseURL    string
	installKey string
	httpClient *http.Client
	workerName string
}

// NewWorkerHTTPClient 创建 Worker HTTP 客户端
func NewWorkerHTTPClient(baseURL, installKey, workerName string) *WorkerHTTPClient {
	return &WorkerHTTPClient{
		baseURL:    baseURL,
		installKey: installKey,
		workerName: workerName,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ==================== Request/Response Types ====================

// TaskCheckReq 任务拉取请求
type TaskCheckReq struct {
	WorkerName string `json:"workerName"`
}

// TaskCheckResp 任务拉取响应
type TaskCheckResp struct {
	Code        int    `json:"code"`
	Msg         string `json:"msg"`
	IsExist     bool   `json:"isExist"`
	IsFinished  bool   `json:"isFinished"`
	TaskId      string `json:"taskId"`
	MainTaskId  string `json:"mainTaskId"`
	WorkspaceId string `json:"workspaceId"`
	Config      string `json:"config"`
}

// TaskUpdateReq 任务状态更新请求
type TaskUpdateReq struct {
	TaskId   string `json:"taskId"`
	State    string `json:"state"`
	Worker   string `json:"worker"`
	Result   string `json:"result"`
	Progress int    `json:"progress"`
	Phase    string `json:"phase"`
}

// TaskUpdateResp 任务状态更新响应
type TaskUpdateResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
}


// IPV4Info IPv4信息
type IPV4Info struct {
	IP       string `json:"ip"`
	IPInt    uint32 `json:"ipInt"`
	Location string `json:"location"`
}

// IPV6Info IPv6信息
type IPV6Info struct {
	IP       string `json:"ip"`
	Location string `json:"location"`
}

// AssetDocument 资产文档
type AssetDocument struct {
	Authority  string     `json:"authority"`
	Host       string     `json:"host"`
	Port       int32      `json:"port"`
	Category   string     `json:"category"`
	Service    string     `json:"service"`
	Server     string     `json:"server"`
	Banner     string     `json:"banner"`
	Title      string     `json:"title"`
	App        []string   `json:"app"`
	HttpStatus string     `json:"httpStatus"`
	HttpHeader string     `json:"httpHeader"`
	HttpBody   string     `json:"httpBody"`
	Cert       string     `json:"cert"`
	IconHash   string     `json:"iconHash"`
	IsCdn      bool       `json:"isCdn"`
	Cname      string     `json:"cname"`
	IsCloud    bool       `json:"isCloud"`
	Ipv4       []IPV4Info `json:"ipv4"`
	Ipv6       []IPV6Info `json:"ipv6"`
	Screenshot string     `json:"screenshot"`
	IsHttp     bool       `json:"isHttp"`
	Source     string     `json:"source"`
	IconData   []byte     `json:"iconData"`
}

// TaskResultReq 资产结果上报请求
type TaskResultReq struct {
	WorkspaceId string          `json:"workspaceId"`
	MainTaskId  string          `json:"mainTaskId"`
	OrgId       string          `json:"orgId"`
	Assets      []AssetDocument `json:"assets"`
}

// TaskResultResp 资产结果上报响应
type TaskResultResp struct {
	Code        int    `json:"code"`
	Msg         string `json:"msg"`
	Success     bool   `json:"success"`
	TotalAsset  int32  `json:"totalAsset"`
	NewAsset    int32  `json:"newAsset"`
	UpdateAsset int32  `json:"updateAsset"`
}

// VulDocument 漏洞文档
type VulDocument struct {
	Authority         string   `json:"authority"`
	Host              string   `json:"host"`
	Port              int32    `json:"port"`
	Url               string   `json:"url"`
	PocFile           string   `json:"pocFile"`
	Source            string   `json:"source"`
	Severity          string   `json:"severity"`
	Extra             string   `json:"extra"`
	Result            string   `json:"result"`
	TaskId            string   `json:"taskId"`
	CvssScore         *float64 `json:"cvssScore,omitempty"`
	CveId             *string  `json:"cveId,omitempty"`
	CweId             *string  `json:"cweId,omitempty"`
	Remediation       *string  `json:"remediation,omitempty"`
	References        []string `json:"references,omitempty"`
	MatcherName       *string  `json:"matcherName,omitempty"`
	ExtractedResults  []string `json:"extractedResults,omitempty"`
	CurlCommand       *string  `json:"curlCommand,omitempty"`
	Request           *string  `json:"request,omitempty"`
	Response          *string  `json:"response,omitempty"`
	ResponseTruncated *bool    `json:"responseTruncated,omitempty"`
}

// VulResultReq 漏洞结果上报请求
type VulResultReq struct {
	WorkspaceId string        `json:"workspaceId"`
	MainTaskId  string        `json:"mainTaskId"`
	Vuls        []VulDocument `json:"vuls"`
}

// VulResultResp 漏洞结果上报响应
type VulResultResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
	Total   int32  `json:"total"`
}


// HeartbeatReq 心跳请求
type HeartbeatReq struct {
	WorkerName         string  `json:"workerName"`
	IP                 string  `json:"ip"`
	CpuLoad            float64 `json:"cpuLoad"`
	MemUsed            float64 `json:"memUsed"`
	TaskStartedNumber  int32   `json:"taskStartedNumber"`
	TaskExecutedNumber int32   `json:"taskExecutedNumber"`
	IsDaemon           bool    `json:"isDaemon"`
	Concurrency        int     `json:"concurrency"`
}

// HeartbeatResp 心跳响应
type HeartbeatResp struct {
	Code              int    `json:"code"`
	Msg               string `json:"msg"`
	Status            string `json:"status"`
	ManualStopFlag    bool   `json:"manualStopFlag"`
	ManualReloadFlag  bool   `json:"manualReloadFlag"`
	ManualInitEnvFlag bool   `json:"manualInitEnvFlag"`
	ManualSyncFlag    bool   `json:"manualSyncFlag"`
}

// SubTaskDoneReq 子任务完成请求
type SubTaskDoneReq struct {
	TaskId      string `json:"taskId"`
	MainTaskId  string `json:"mainTaskId"`
	WorkspaceId string `json:"workspaceId"`
	Phase       string `json:"phase"`
}

// SubTaskDoneResp 子任务完成响应
type SubTaskDoneResp struct {
	Code         int    `json:"code"`
	Msg          string `json:"msg"`
	Success      bool   `json:"success"`
	SubTaskDone  int32  `json:"subTaskDone"`
	SubTaskCount int32  `json:"subTaskCount"`
	AllDone      bool   `json:"allDone"`
}

// TemplatesReq 模板获取请求
type TemplatesReq struct {
	Tags              []string `json:"tags,omitempty"`
	Severities        []string `json:"severities,omitempty"`
	NucleiTemplateIds []string `json:"nucleiTemplateIds,omitempty"`
	CustomPocIds      []string `json:"customPocIds,omitempty"`
}

// TemplatesResp 模板获取响应
type TemplatesResp struct {
	Code      int      `json:"code"`
	Msg       string   `json:"msg"`
	Success   bool     `json:"success"`
	Templates []string `json:"templates"`
	Count     int32    `json:"count"`
}

// FingerprintsReq 指纹获取请求
type FingerprintsReq struct {
	EnabledOnly bool `json:"enabledOnly"`
}

// FingerprintDocument 指纹文档
type FingerprintDocument struct {
	Id        string            `json:"id"`
	Name      string            `json:"name"`
	Category  string            `json:"category"`
	Rule      string            `json:"rule"`
	Source    string            `json:"source"`
	Headers   map[string]string `json:"headers"`
	Cookies   map[string]string `json:"cookies"`
	Html      []string          `json:"html"`
	Scripts   []string          `json:"scripts"`
	ScriptSrc []string          `json:"scriptSrc"`
	Meta      map[string]string `json:"meta"`
	Css       []string          `json:"css"`
	Url       []string          `json:"url"`
	IsBuiltin bool              `json:"isBuiltin"`
	Enabled   bool              `json:"enabled"`
}

// FingerprintsResp 指纹获取响应
type FingerprintsResp struct {
	Code         int                   `json:"code"`
	Msg          string                `json:"msg"`
	Success      bool                  `json:"success"`
	Fingerprints []FingerprintDocument `json:"fingerprints"`
	Count        int32                 `json:"count"`
}


// SubfinderReq Subfinder配置获取请求
type SubfinderReq struct {
	WorkspaceId string `json:"workspaceId"`
}

// SubfinderProvider Subfinder数据源
type SubfinderProvider struct {
	Id          string   `json:"id"`
	Provider    string   `json:"provider"`
	Keys        []string `json:"keys"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
}

// SubfinderResp Subfinder配置获取响应
type SubfinderResp struct {
	Code      int                 `json:"code"`
	Msg       string              `json:"msg"`
	Success   bool                `json:"success"`
	Providers []SubfinderProvider `json:"providers"`
	Count     int32               `json:"count"`
}

// HttpServiceReq HTTP服务映射获取请求
type HttpServiceReq struct {
	EnabledOnly bool `json:"enabledOnly"`
}

// HttpServiceMapping HTTP服务映射
type HttpServiceMapping struct {
	Id          string `json:"id"`
	ServiceName string `json:"serviceName"`
	IsHttp      bool   `json:"isHttp"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// HttpServiceResp HTTP服务映射获取响应
type HttpServiceResp struct {
	Code     int                  `json:"code"`
	Msg      string               `json:"msg"`
	Success  bool                 `json:"success"`
	Mappings []HttpServiceMapping `json:"mappings"`
	Count    int32                `json:"count"`
}

// PocByIdReq POC获取请求
type PocByIdReq struct {
	PocId   string `json:"pocId"`
	PocType string `json:"pocType"`
}

// PocByIdResp POC获取响应
type PocByIdResp struct {
	Code     int    `json:"code"`
	Msg      string `json:"msg"`
	Success  bool   `json:"success"`
	Content  string `json:"content"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	PocType  string `json:"pocType"`
}


// ==================== HTTP Client Methods ====================

// RetryConfig 重试配置
type RetryConfig struct {
	MaxRetries     int           // 最大重试次数
	InitialBackoff time.Duration // 初始退避时间
	MaxBackoff     time.Duration // 最大退避时间
	BackoffFactor  float64       // 退避因子
}

// DefaultRetryConfig 默认重试配置
var DefaultRetryConfig = RetryConfig{
	MaxRetries:     3,
	InitialBackoff: 1 * time.Second,
	MaxBackoff:     30 * time.Second,
	BackoffFactor:  2.0,
}

// isRetryableError 判断是否为可重试的错误
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// 连接错误、超时错误可重试
	errStr := err.Error()
	return contains(errStr, "connection refused") ||
		contains(errStr, "connection reset") ||
		contains(errStr, "timeout") ||
		contains(errStr, "no such host") ||
		contains(errStr, "network is unreachable") ||
		contains(errStr, "i/o timeout")
}

// contains 检查字符串是否包含子串（不区分大小写）
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsLower(s, substr)))
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if matchLower(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func matchLower(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// doRequest 执行HTTP请求（内部方法，带重试逻辑）
func (c *WorkerHTTPClient) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	return c.doRequestWithRetry(ctx, method, path, body, DefaultRetryConfig)
}

// doRequestWithRetry 执行HTTP请求（带自定义重试配置）
func (c *WorkerHTTPClient) doRequestWithRetry(ctx context.Context, method, path string, body interface{}, retryConfig RetryConfig) ([]byte, error) {
	var lastErr error
	backoff := retryConfig.InitialBackoff

	for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
		// 检查上下文是否已取消
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// 如果不是第一次尝试，等待退避时间
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			// 计算下一次退避时间
			backoff = time.Duration(float64(backoff) * retryConfig.BackoffFactor)
			if backoff > retryConfig.MaxBackoff {
				backoff = retryConfig.MaxBackoff
			}
		}

		respBody, err := c.doRequestOnce(ctx, method, path, body)
		if err == nil {
			return respBody, nil
		}

		lastErr = err

		// 认证失败不重试
		if err.Error() == "authentication failed: invalid install key" {
			return nil, err
		}

		// 判断是否可重试
		if !isRetryableError(err) {
			return nil, err
		}

		// 记录重试日志
		if attempt < retryConfig.MaxRetries {
			fmt.Printf("[HTTPClient] Request failed (attempt %d/%d): %v, retrying in %v...\n",
				attempt+1, retryConfig.MaxRetries+1, err, backoff)
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", retryConfig.MaxRetries+1, lastErr)
}

// doRequestOnce 执行单次HTTP请求
func (c *WorkerHTTPClient) doRequestOnce(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body failed: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Worker-Key", c.installKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body failed: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid install key")
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// CheckTask 任务拉取
func (c *WorkerHTTPClient) CheckTask(ctx context.Context) (*TaskCheckResp, error) {
	req := &TaskCheckReq{
		WorkerName: c.workerName,
	}

	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/task/check", req)
	if err != nil {
		return nil, err
	}

	var resp TaskCheckResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// UpdateTask 任务状态更新
func (c *WorkerHTTPClient) UpdateTask(ctx context.Context, req *TaskUpdateReq) (*TaskUpdateResp, error) {
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/task/update", req)
	if err != nil {
		return nil, err
	}

	var resp TaskUpdateResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// SaveTaskResult 保存资产结果
func (c *WorkerHTTPClient) SaveTaskResult(ctx context.Context, req *TaskResultReq) (*TaskResultResp, error) {
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/task/result", req)
	if err != nil {
		return nil, err
	}

	var resp TaskResultResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// SaveVulResult 保存漏洞结果
func (c *WorkerHTTPClient) SaveVulResult(ctx context.Context, req *VulResultReq) (*VulResultResp, error) {
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/task/vul", req)
	if err != nil {
		return nil, err
	}

	var resp VulResultResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}


// Heartbeat 心跳
func (c *WorkerHTTPClient) Heartbeat(ctx context.Context, req *HeartbeatReq) (*HeartbeatResp, error) {
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/heartbeat", req)
	if err != nil {
		return nil, err
	}

	var resp HeartbeatResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// IncrSubTaskDone 递增子任务完成数
func (c *WorkerHTTPClient) IncrSubTaskDone(ctx context.Context, req *SubTaskDoneReq) (*SubTaskDoneResp, error) {
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/task/subtask/done", req)
	if err != nil {
		return nil, err
	}

	var resp SubTaskDoneResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// GetTemplates 获取POC模板
func (c *WorkerHTTPClient) GetTemplates(ctx context.Context, req *TemplatesReq) (*TemplatesResp, error) {
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/config/templates", req)
	if err != nil {
		return nil, err
	}

	var resp TemplatesResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// GetFingerprints 获取指纹配置
func (c *WorkerHTTPClient) GetFingerprints(ctx context.Context, req *FingerprintsReq) (*FingerprintsResp, error) {
	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/config/fingerprints", req)
	if err != nil {
		return nil, err
	}

	var resp FingerprintsResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// GetSubfinderProviders 获取Subfinder配置
func (c *WorkerHTTPClient) GetSubfinderProviders(ctx context.Context, workspaceId string) (*SubfinderResp, error) {
	req := &SubfinderReq{
		WorkspaceId: workspaceId,
	}

	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/config/subfinder", req)
	if err != nil {
		return nil, err
	}

	var resp SubfinderResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// GetHttpServiceMappings 获取HTTP服务映射
func (c *WorkerHTTPClient) GetHttpServiceMappings(ctx context.Context, enabledOnly bool) (*HttpServiceResp, error) {
	req := &HttpServiceReq{
		EnabledOnly: enabledOnly,
	}

	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/config/httpservice", req)
	if err != nil {
		return nil, err
	}

	var resp HttpServiceResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// GetPocById 根据ID获取POC
func (c *WorkerHTTPClient) GetPocById(ctx context.Context, pocId, pocType string) (*PocByIdResp, error) {
	req := &PocByIdReq{
		PocId:   pocId,
		PocType: pocType,
	}

	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/config/poc", req)
	if err != nil {
		return nil, err
	}

	var resp PocByIdResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// ==================== Worker Offline Notification ====================

// WorkerOfflineReq Worker离线通知请求
type WorkerOfflineReq struct {
	WorkerName string `json:"workerName"`
}

// WorkerOfflineResp Worker离线通知响应
type WorkerOfflineResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
}

// NotifyOffline 通知服务器Worker即将离线
func (c *WorkerHTTPClient) NotifyOffline(ctx context.Context) (*WorkerOfflineResp, error) {
	req := &WorkerOfflineReq{
		WorkerName: c.workerName,
	}

	// 使用较短的超时，避免阻塞停止流程
	shortCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	respBody, err := c.doRequestOnce(shortCtx, http.MethodPost, "/api/v1/worker/offline", req)
	if err != nil {
		return nil, err
	}

	var resp WorkerOfflineResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}

// ==================== Task Control Polling ====================

// TaskControlReq 任务控制信号请求
type TaskControlReq struct {
	WorkerName string   `json:"workerName"`
	TaskIds    []string `json:"taskIds"` // 当前正在执行的任务ID列表
}

// TaskControlSignal 单个任务的控制信号
type TaskControlSignal struct {
	TaskId string `json:"taskId"`
	Action string `json:"action"` // STOP, PAUSE, RESUME
}

// TaskControlResp 任务控制信号响应
type TaskControlResp struct {
	Code    int                 `json:"code"`
	Msg     string              `json:"msg"`
	Success bool                `json:"success"`
	Signals []TaskControlSignal `json:"signals"`
}

// GetTaskControlSignals 获取任务控制信号（HTTP轮询）
func (c *WorkerHTTPClient) GetTaskControlSignals(ctx context.Context, taskIds []string) (*TaskControlResp, error) {
	req := &TaskControlReq{
		WorkerName: c.workerName,
		TaskIds:    taskIds,
	}

	respBody, err := c.doRequest(ctx, http.MethodPost, "/api/v1/worker/task/control", req)
	if err != nil {
		return nil, err
	}

	var resp TaskControlResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	return &resp, nil
}
