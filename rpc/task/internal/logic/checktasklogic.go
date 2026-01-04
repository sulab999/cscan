package logic

import (
	"context"
	"encoding/json"
	"strings"

	"cscan/rpc/task/internal/svc"
	"cscan/rpc/task/pb"
	"cscan/scheduler"

	"github.com/zeromicro/go-zero/core/logx"
)

type CheckTaskLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewCheckTaskLogic(ctx context.Context, svcCtx *svc.ServiceContext) *CheckTaskLogic {
	return &CheckTaskLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// 检查任务状态 - 从Redis队列中获取待执行的任务
func (l *CheckTaskLogic) CheckTask(in *pb.CheckTaskReq) (*pb.CheckTaskResp, error) {
	workerName := in.TaskId // TaskId 实际上是 Worker 名称

	// 从 Redis 队列中获取优先级最高的任务
	queueKey := "cscan:task:queue"
	results, err := l.svcCtx.RedisClient.ZRange(l.ctx, queueKey, 0, -1).Result()
	if err != nil {
		l.Logger.Errorf("CheckTask: failed to get tasks from queue: %v", err)
		return &pb.CheckTaskResp{IsExist: false}, nil
	}

	// 遍历队列中的任务，找到可以执行的任务
	for _, taskData := range results {
		var task scheduler.TaskInfo
		if err := json.Unmarshal([]byte(taskData), &task); err != nil {
			continue
		}

		// 检查任务是否指定了 Worker
		if len(task.Workers) > 0 {
			// 检查当前 Worker 是否在指定列表中
			found := false
			for _, w := range task.Workers {
				if strings.EqualFold(w, workerName) {
					found = true
					break
				}
			}
			if !found {
				continue // 当前 Worker 不在指定列表中，跳过
			}
		}

		// 从队列中移除该任务
		removed, err := l.svcCtx.RedisClient.ZRem(l.ctx, queueKey, taskData).Result()
		if err != nil || removed == 0 {
			// 任务可能已被其他 Worker 取走
			continue
		}

		// 添加到处理中集合
		processingKey := "cscan:task:processing"
		l.svcCtx.RedisClient.SAdd(l.ctx, processingKey, task.TaskId)

		l.Logger.Infof("CheckTask: assigned task %s to worker %s", task.TaskId, workerName)

		return &pb.CheckTaskResp{
			IsExist:     true,
			IsFinished:  false,
			TaskId:      task.TaskId,
			MainTaskId:  task.MainTaskId,
			WorkspaceId: task.WorkspaceId,
			Config:      task.Config,
		}, nil
	}

	// 没有可执行的任务
	return &pb.CheckTaskResp{IsExist: false}, nil
}
