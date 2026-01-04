package worker

import (
	"encoding/json"
	"net/http"

	"cscan/api/internal/svc"
	"cscan/pkg/response"
	"cscan/rpc/task/pb"

	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

// ==================== Worker Task Types ====================

// WorkerTaskCheckReq 任务拉取请求
type WorkerTaskCheckReq struct {
	WorkerName string `json:"workerName"`
}

// WorkerTaskCheckResp 任务拉取响应
type WorkerTaskCheckResp struct {
	Code        int    `json:"code"`
	Msg         string `json:"msg"`
	IsExist     bool   `json:"isExist"`
	IsFinished  bool   `json:"isFinished"`
	TaskId      string `json:"taskId"`
	MainTaskId  string `json:"mainTaskId"`
	WorkspaceId string `json:"workspaceId"`
	Config      string `json:"config"`
}

// WorkerTaskUpdateReq 任务状态更新请求
type WorkerTaskUpdateReq struct {
	TaskId   string `json:"taskId"`
	State    string `json:"state"`    // started, success, failure, paused
	Worker   string `json:"worker"`
	Result   string `json:"result"`
	Progress int    `json:"progress"` // 0-100
	Phase    string `json:"phase"`    // 当前阶段描述
}

// WorkerTaskUpdateResp 任务状态更新响应
type WorkerTaskUpdateResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
}

// ==================== Task Check Handler ====================

// WorkerTaskCheckHandler 任务拉取接口
// POST /api/v1/worker/task/check
func WorkerTaskCheckHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerTaskCheckReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerTaskCheckResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.WorkerName == "" {
			httpx.OkJson(w, &WorkerTaskCheckResp{Code: 400, Msg: "workerName不能为空"})
			return
		}

		// 调用RPC CheckTask
		rpcReq := &pb.CheckTaskReq{
			TaskId:     "",
			MainTaskId: "",
		}

		rpcResp, err := svcCtx.TaskRpcClient.CheckTask(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerTaskCheck] RPC CheckTask error: %v", err)
			response.Error(w, err)
			return
		}

		httpx.OkJson(w, &WorkerTaskCheckResp{
			Code:        0,
			Msg:         "success",
			IsExist:     rpcResp.IsExist,
			IsFinished:  rpcResp.IsFinished,
			TaskId:      rpcResp.TaskId,
			MainTaskId:  rpcResp.MainTaskId,
			WorkspaceId: rpcResp.WorkspaceId,
			Config:      rpcResp.Config,
		})
	}
}

// ==================== Task Update Handler ====================

// WorkerTaskUpdateHandler 任务状态更新接口
// POST /api/v1/worker/task/update
func WorkerTaskUpdateHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerTaskUpdateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerTaskUpdateResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.TaskId == "" {
			httpx.OkJson(w, &WorkerTaskUpdateResp{Code: 400, Msg: "taskId不能为空"})
			return
		}

		// 调用RPC UpdateTask
		rpcReq := &pb.UpdateTaskReq{
			TaskId: req.TaskId,
			State:  req.State,
			Worker: req.Worker,
			Result: req.Result,
		}

		rpcResp, err := svcCtx.TaskRpcClient.UpdateTask(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerTaskUpdate] RPC UpdateTask error: %v", err)
			response.Error(w, err)
			return
		}

		httpx.OkJson(w, &WorkerTaskUpdateResp{
			Code:    0,
			Msg:     rpcResp.Message,
			Success: rpcResp.Success,
		})
	}
}

// ==================== Task Control Handler ====================

// WorkerTaskControlReq 任务控制信号请求
type WorkerTaskControlReq struct {
	WorkerName string   `json:"workerName"`
	TaskIds    []string `json:"taskIds"` // 当前正在执行的任务ID列表
}

// TaskControlSignal 单个任务的控制信号
type TaskControlSignal struct {
	TaskId string `json:"taskId"`
	Action string `json:"action"` // STOP, PAUSE, RESUME
}

// WorkerTaskControlResp 任务控制信号响应
type WorkerTaskControlResp struct {
	Code    int                 `json:"code"`
	Msg     string              `json:"msg"`
	Success bool                `json:"success"`
	Signals []TaskControlSignal `json:"signals"`
}

// WorkerTaskControlHandler 任务控制信号轮询接口
// POST /api/v1/worker/task/control
// 用于WebSocket不可用时的HTTP轮询回退
func WorkerTaskControlHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerTaskControlReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerTaskControlResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if len(req.TaskIds) == 0 {
			httpx.OkJson(w, &WorkerTaskControlResp{
				Code:    0,
				Msg:     "success",
				Success: true,
				Signals: []TaskControlSignal{},
			})
			return
		}

		// 从Redis检查每个任务的控制信号
		var signals []TaskControlSignal
		ctx := r.Context()

		for _, taskId := range req.TaskIds {
			// 检查Redis中是否有该任务的控制信号
			// 控制信号存储在 cscan:task:ctrl:{taskId} 键中
			ctrlKey := "cscan:task:ctrl:" + taskId
			action, err := svcCtx.RedisClient.Get(ctx, ctrlKey).Result()
			if err == nil && action != "" {
				signals = append(signals, TaskControlSignal{
					TaskId: taskId,
					Action: action,
				})
			}
		}

		httpx.OkJson(w, &WorkerTaskControlResp{
			Code:    0,
			Msg:     "success",
			Success: true,
			Signals: signals,
		})
	}
}
