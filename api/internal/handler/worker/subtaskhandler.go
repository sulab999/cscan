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

// ==================== SubTask Types ====================

// WorkerSubTaskDoneReq 子任务完成请求
type WorkerSubTaskDoneReq struct {
	TaskId      string `json:"taskId"`
	MainTaskId  string `json:"mainTaskId"`
	WorkspaceId string `json:"workspaceId"`
	Phase       string `json:"phase"`
}

// WorkerSubTaskDoneResp 子任务完成响应
type WorkerSubTaskDoneResp struct {
	Code         int    `json:"code"`
	Msg          string `json:"msg"`
	Success      bool   `json:"success"`
	SubTaskDone  int32  `json:"subTaskDone"`
	SubTaskCount int32  `json:"subTaskCount"`
	AllDone      bool   `json:"allDone"`
}

// ==================== SubTask Handler ====================

// WorkerSubTaskDoneHandler 子任务进度接口
// POST /api/v1/worker/task/subtask/done
func WorkerSubTaskDoneHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerSubTaskDoneReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerSubTaskDoneResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.TaskId == "" || req.MainTaskId == "" {
			httpx.OkJson(w, &WorkerSubTaskDoneResp{Code: 400, Msg: "taskId和mainTaskId不能为空"})
			return
		}

		// 调用RPC IncrSubTaskDone
		rpcReq := &pb.IncrSubTaskDoneReq{
			TaskId:      req.TaskId,
			MainTaskId:  req.MainTaskId,
			WorkspaceId: req.WorkspaceId,
			Phase:       req.Phase,
		}

		rpcResp, err := svcCtx.TaskRpcClient.IncrSubTaskDone(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerSubTaskDone] RPC IncrSubTaskDone error: %v", err)
			response.Error(w, err)
			return
		}

		httpx.OkJson(w, &WorkerSubTaskDoneResp{
			Code:         0,
			Msg:          rpcResp.Message,
			Success:      rpcResp.Success,
			SubTaskDone:  rpcResp.SubTaskDone,
			SubTaskCount: rpcResp.SubTaskCount,
			AllDone:      rpcResp.AllDone,
		})
	}
}
