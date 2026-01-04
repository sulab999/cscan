package logic

import (
	"context"
	"encoding/json"

	"cscan/rpc/task/internal/svc"
	"cscan/rpc/task/pb"

	"github.com/zeromicro/go-zero/core/logx"
)

type GetPocValidationResultLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewGetPocValidationResultLogic(ctx context.Context, svcCtx *svc.ServiceContext) *GetPocValidationResultLogic {
	return &GetPocValidationResultLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// 查询POC验证结果
func (l *GetPocValidationResultLogic) GetPocValidationResult(in *pb.GetPocValidationResultReq) (*pb.GetPocValidationResultResp, error) {
	taskId := in.TaskId
	if taskId == "" {
		return &pb.GetPocValidationResultResp{
			Success: false,
			Message: "TaskId不能为空",
			Status:  "ERROR",
		}, nil
	}

	// 从Redis获取任务状态（与UpdateTask保存的key一致）
	statusKey := "cscan:task:status:" + taskId
	statusData, err := l.svcCtx.RedisClient.Get(l.ctx, statusKey).Result()
	if err != nil {
		// 检查任务是否还在执行中
		taskInfoKey := "cscan:task:info:" + taskId
		taskInfoData, infoErr := l.svcCtx.RedisClient.Get(l.ctx, taskInfoKey).Result()
		if infoErr == nil && taskInfoData != "" {
			var taskInfo map[string]interface{}
			if json.Unmarshal([]byte(taskInfoData), &taskInfo) == nil {
				status, _ := taskInfo["status"].(string)
				if status == "" || status == "PENDING" || status == "STARTED" {
					// 任务还在执行中
					return &pb.GetPocValidationResultResp{
						Success: true,
						Message: "任务执行中",
						Status:  "RUNNING",
					}, nil
				}
			}
		}
		// 未找到结果
		return &pb.GetPocValidationResultResp{
			Success: false,
			Message: "未找到验证结果",
			Status:  "NOT_FOUND",
		}, nil
	}

	// 解析状态数据
	var statusInfo map[string]interface{}
	if err := json.Unmarshal([]byte(statusData), &statusInfo); err != nil {
		return &pb.GetPocValidationResultResp{
			Success: false,
			Message: "解析状态失败",
			Status:  "ERROR",
		}, nil
	}

	// 获取状态
	state, _ := statusInfo["state"].(string)
	if state == "" {
		state = "RUNNING"
	}

	// 将内部状态映射到前端期望的状态
	status := state
	if state == "COMPLETED" {
		status = "SUCCESS"
	}

	// 解析结果数据（result字段包含JSON格式的验证结果）
	var pbResults []*pb.PocValidationResult
	resultStr, _ := statusInfo["result"].(string)
	if resultStr != "" {
		var resultData map[string]interface{}
		if json.Unmarshal([]byte(resultStr), &resultData) == nil {
			// 从result中获取实际状态（如果有）
			if resultStatus, ok := resultData["status"].(string); ok && resultStatus != "" {
				status = resultStatus
			}
			// 解析验证结果列表
			if results, ok := resultData["results"].([]interface{}); ok {
				for _, r := range results {
					if rMap, ok := r.(map[string]interface{}); ok {
						pbResult := &pb.PocValidationResult{
							PocId:      getString(rMap, "pocId"),
							PocName:    getString(rMap, "pocName"),
							TemplateId: getString(rMap, "templateId"),
							Severity:   getString(rMap, "severity"),
							Matched:    getBool(rMap, "matched"),
							MatchedUrl: getString(rMap, "matchedUrl"),
							Details:    getString(rMap, "details"),
							Output:     getString(rMap, "output"),
							PocType:    getString(rMap, "pocType"),
						}
						if tags, ok := rMap["tags"].([]interface{}); ok {
							for _, t := range tags {
								if s, ok := t.(string); ok {
									pbResult.Tags = append(pbResult.Tags, s)
								}
							}
						}
						pbResults = append(pbResults, pbResult)
					}
				}
			}
		}
	}

	return &pb.GetPocValidationResultResp{
		Success:        true,
		Message:        "success",
		Status:         status,
		Results:        pbResults,
		CompletedCount: int32(len(pbResults)),
		TotalCount:     int32(len(pbResults)),
	}, nil
}

// 辅助函数：安全获取字符串
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// 辅助函数：安全获取布尔值
func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}
