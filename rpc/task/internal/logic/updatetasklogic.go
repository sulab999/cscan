package logic

import (
	"context"
	"encoding/json"
	"time"

	"cscan/rpc/task/internal/svc"
	"cscan/rpc/task/pb"
	"cscan/scheduler"

	"github.com/zeromicro/go-zero/core/logx"
	"go.mongodb.org/mongo-driver/bson"
)

type UpdateTaskLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewUpdateTaskLogic(ctx context.Context, svcCtx *svc.ServiceContext) *UpdateTaskLogic {
	return &UpdateTaskLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// 更新任务状态
func (l *UpdateTaskLogic) UpdateTask(in *pb.UpdateTaskReq) (*pb.UpdateTaskResp, error) {
	taskId := in.TaskId
	state := in.State

	l.Logger.Infof("UpdateTask: taskId=%s, state=%s", taskId, state)

	// 从处理中集合移除
	processingKey := "cscan:task:processing"
	l.svcCtx.RedisClient.SRem(l.ctx, processingKey, taskId)

	// 更新任务状态到Redis
	statusKey := "cscan:task:status:" + taskId
	statusData := map[string]interface{}{
		"taskId": taskId,
		"state":  state,
		"worker": in.Worker,
		"result": in.Result,
	}
	statusJson, _ := json.Marshal(statusData)
	l.svcCtx.RedisClient.Set(l.ctx, statusKey, statusJson, 0)

	// 如果任务完成或失败，添加到完成集合
	if state == "SUCCESS" || state == "FAILURE" || state == "COMPLETED" {
		completedKey := "cscan:task:completed"
		taskInfo := scheduler.TaskInfo{
			TaskId: taskId,
		}
		taskJson, _ := json.Marshal(taskInfo)
		l.svcCtx.RedisClient.SAdd(l.ctx, completedKey, string(taskJson))
	}

	// 更新数据库中的任务状态（包括开始时间、结束时间、进度）
	l.updateTaskInDB(taskId, state, in.Result)

	return &pb.UpdateTaskResp{
		Success: true,
		Message: "Task status updated",
	}, nil
}

// updateTaskInDB 更新数据库中的任务状态
func (l *UpdateTaskLogic) updateTaskInDB(taskId, state, result string) {
	// 从Redis获取任务信息（workspaceId）
	taskInfoKey := "cscan:task:info:" + taskId
	taskInfoData, err := l.svcCtx.RedisClient.Get(l.ctx, taskInfoKey).Result()
	if err != nil {
		l.Logger.Errorf("UpdateTask: failed to get task info from Redis, taskId=%s, error=%v", taskId, err)
		return
	}

	var taskInfo map[string]interface{}
	if err := json.Unmarshal([]byte(taskInfoData), &taskInfo); err != nil {
		l.Logger.Errorf("UpdateTask: failed to parse task info, taskId=%s, error=%v", taskId, err)
		return
	}

	workspaceId, _ := taskInfo["workspaceId"].(string)
	mainTaskId, _ := taskInfo["mainTaskId"].(string) // MongoDB ObjectID (Hex)
	subTaskCount := 1
	if count, ok := taskInfo["subTaskCount"].(float64); ok {
		subTaskCount = int(count)
	}
	if workspaceId == "" {
		l.Logger.Errorf("UpdateTask: workspaceId is empty, taskId=%s", taskId)
		return
	}

	// 获取任务模型
	taskModel := l.svcCtx.GetMainTaskModel(workspaceId)
	now := time.Now()

	// 构建更新字段
	update := bson.M{
		"status": state,
	}

	l.Logger.Infof("UpdateTask: taskId=%s, mainTaskId=%s, subTaskCount=%d", taskId, mainTaskId, subTaskCount)

	// 根据状态设置不同字段
	switch state {
	case "STARTED":
		// 任务开始时设置开始时间和状态
		// 检查主任务当前状态，如果已经是STARTED则不重复设置
		task, err := taskModel.FindById(l.ctx, mainTaskId)
		if err != nil {
			l.Logger.Errorf("UpdateTask: failed to find task, mainTaskId=%s, error=%v", mainTaskId, err)
			// 查询失败时仍然尝试更新状态和开始时间
			update["start_time"] = now
		} else if task.Status == "STARTED" {
			// 主任务已经是STARTED状态，不需要再更新状态
			delete(update, "status")
			// 但仍然更新 update_time（在 taskModel.Update 中自动添加）
		} else {
			// 主任务不是STARTED状态（如PENDING），更新状态和开始时间
			update["start_time"] = now
		}
	case "SUCCESS", "COMPLETED":
		// 如果有多个子任务（subTaskCount > 1），不在这里更新主任务状态
		// 主任务的完成状态由 IncrSubTaskDone 在所有子任务完成后设置
		if subTaskCount > 1 {
			l.Logger.Infof("UpdateTask: task %s has %d sub-tasks, skipping status update (managed by IncrSubTaskDone)", taskId, subTaskCount)
			return
		}
		// 单任务（subTaskCount <= 1）完成时设置结束时间
		update["end_time"] = now
		update["result"] = result
	case "FAILURE":
		// 任务失败时设置结束时间
		update["end_time"] = now
		update["result"] = result
	case "STOPPED":
		// 任务停止时设置结束时间
		update["end_time"] = now
		update["result"] = "任务已停止"
	}

	// 更新数据库，mainTaskId 是 MongoDB ObjectID
	if mainTaskId != "" {
		if err := taskModel.Update(l.ctx, mainTaskId, update); err != nil {
			l.Logger.Errorf("UpdateTask: failed to update task in DB, mainTaskId=%s, error=%v", mainTaskId, err)
		} else {
			l.Logger.Infof("UpdateTask: task updated in DB, mainTaskId=%s, state=%s", mainTaskId, state)
		}
	}
}
