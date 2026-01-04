package worker

import (
	"fmt"
	"net/http"
	"time"

	"cscan/api/internal/svc"
	"cscan/pkg/response"
)

// WorkerConsoleInfoResp Worker控制台信息响应
type WorkerConsoleInfoResp struct {
	Name         string          `json:"name"`
	IP           string          `json:"ip"`
	OS           string          `json:"os"`
	Arch         string          `json:"arch"`
	Version      string          `json:"version"`
	Hostname     string          `json:"hostname"`
	Uptime       int64           `json:"uptime"`
	SystemUptime int64           `json:"systemUptime"`
	CpuCores     int             `json:"cpuCores"`
	CpuLoad      float64         `json:"cpuLoad"`
	MemTotal     uint64          `json:"memTotal"`
	MemUsed      uint64          `json:"memUsed"`
	MemPercent   float64         `json:"memPercent"`
	DiskTotal    uint64          `json:"diskTotal"`
	DiskUsed     uint64          `json:"diskUsed"`
	DiskPercent  float64         `json:"diskPercent"`
	TaskStarted  int             `json:"taskStarted"`
	TaskRunning  int             `json:"taskRunning"`
	Tools        map[string]bool `json:"tools"`
	Online       bool            `json:"online"`
}

// WorkerConsoleInfoHandler Worker控制台信息接口
// GET /api/v1/worker/console/info?name=xxx
func WorkerConsoleInfoHandler(svcCtx *svc.ServiceContext, wsHandler *WorkerWSHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 从URL查询参数获取Worker名称
		workerName := r.URL.Query().Get("name")
		if workerName == "" {
			response.ParamError(w, "worker name is required")
			return
		}

		// 获取Worker连接
		conn, ok := wsHandler.GetConnection(workerName)
		if !ok {
			// Worker不在线，返回离线状态
			response.Success(w, &WorkerConsoleInfoResp{
				Name:   workerName,
				Online: false,
			})
			return
		}

		// 请求Worker信息（超时10秒）
		info, err := conn.RequestWorkerInfo(10 * time.Second)
		if err != nil {
			response.Error(w, fmt.Errorf("failed to get worker info: %w", err))
			return
		}

		// 构建响应
		resp := &WorkerConsoleInfoResp{
			Name:         info.Name,
			IP:           info.IP,
			OS:           info.OS,
			Arch:         info.Arch,
			Version:      info.Version,
			Hostname:     info.Hostname,
			Uptime:       info.Uptime,
			SystemUptime: info.SystemUptime,
			CpuCores:     info.CpuCores,
			CpuLoad:      info.CpuLoad,
			MemTotal:     info.MemTotal,
			MemUsed:      info.MemUsed,
			MemPercent:   info.MemPercent,
			DiskTotal:    info.DiskTotal,
			DiskUsed:     info.DiskUsed,
			DiskPercent:  info.DiskPercent,
			TaskStarted:  info.TaskStarted,
			TaskRunning:  info.TaskRunning,
			Tools:        info.Tools,
			Online:       true,
		}

		response.Success(w, resp)
	}
}
