package worker

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"cscan/api/internal/logic"
	"cscan/api/internal/svc"
	"cscan/api/internal/types"

	"github.com/zeromicro/go-zero/rest/httpx"
)

// WorkerInstallCommandHandler 获取Worker安装命令
func WorkerInstallCommandHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.WorkerInstallCommandReq
		if err := httpx.Parse(r, &req); err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
			return
		}

		l := logic.NewWorkerInstallLogic(r.Context(), svcCtx)
		resp, err := l.GetInstallCommand(&req)
		if err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
		} else {
			httpx.OkJsonCtx(r.Context(), w, resp)
		}
	}
}

// WorkerRefreshKeyHandler 刷新安装密钥
func WorkerRefreshKeyHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := logic.NewWorkerInstallLogic(r.Context(), svcCtx)
		resp, err := l.RefreshInstallKey()
		if err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
		} else {
			httpx.OkJsonCtx(r.Context(), w, resp)
		}
	}
}

// WorkerValidateKeyHandler 验证安装密钥（Worker调用）
func WorkerValidateKeyHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.WorkerValidateKeyReq
		if err := httpx.Parse(r, &req); err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
			return
		}

		l := logic.NewWorkerInstallLogic(r.Context(), svcCtx)
		resp, err := l.ValidateInstallKey(&req)
		if err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
		} else {
			httpx.OkJsonCtx(r.Context(), w, resp)
		}
	}
}

// WorkerDownloadHandler Worker二进制下载
func WorkerDownloadHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 获取请求参数
		osType := r.URL.Query().Get("os")
		arch := r.URL.Query().Get("arch")

		// 默认值
		if osType == "" {
			osType = runtime.GOOS
		}
		if arch == "" {
			arch = runtime.GOARCH
		}

		// 构建文件名
		filename := "cscan-worker"
		if osType == "windows" {
			filename = "cscan-worker.exe"
		}

		// 构建二进制文件路径
		// 支持多种路径：
		// 1. ./bin/{os}_{arch}/cscan-worker
		// 2. ./cscan-worker (当前目录)
		// 3. /app/cscan-worker (Docker环境)
		var binaryPath string
		possiblePaths := []string{
			filepath.Join("bin", osType+"_"+arch, filename),
			filepath.Join("bin", filename),
			filename,
			filepath.Join("/app", filename),
		}

		for _, p := range possiblePaths {
			if _, err := os.Stat(p); err == nil {
				binaryPath = p
				break
			}
		}

		if binaryPath == "" {
			http.Error(w, "Worker binary not found for "+osType+"_"+arch, http.StatusNotFound)
			return
		}

		// 打开文件
		file, err := os.Open(binaryPath)
		if err != nil {
			http.Error(w, "Failed to open binary: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// 获取文件信息
		fileInfo, err := file.Stat()
		if err != nil {
			http.Error(w, "Failed to get file info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 设置响应头
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

		// 发送文件
		io.Copy(w, file)
	}
}
