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

// ==================== Templates Config Types ====================

// WorkerTemplatesReq 模板获取请求
type WorkerTemplatesReq struct {
	// 按标签获取
	Tags       []string `json:"tags,omitempty"`
	Severities []string `json:"severities,omitempty"`
	// 按ID获取
	NucleiTemplateIds []string `json:"nucleiTemplateIds,omitempty"`
	CustomPocIds      []string `json:"customPocIds,omitempty"`
}

// WorkerTemplatesResp 模板获取响应
type WorkerTemplatesResp struct {
	Code      int      `json:"code"`
	Msg       string   `json:"msg"`
	Success   bool     `json:"success"`
	Templates []string `json:"templates"`
	Count     int32    `json:"count"`
}

// ==================== Fingerprints Config Types ====================

// WorkerFingerprintsReq 指纹获取请求
type WorkerFingerprintsReq struct {
	EnabledOnly bool `json:"enabledOnly"`
}

// WorkerFingerprintDocument 指纹文档
type WorkerFingerprintDocument struct {
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

// WorkerFingerprintsResp 指纹获取响应
type WorkerFingerprintsResp struct {
	Code         int                         `json:"code"`
	Msg          string                      `json:"msg"`
	Success      bool                        `json:"success"`
	Fingerprints []WorkerFingerprintDocument `json:"fingerprints"`
	Count        int32                       `json:"count"`
}

// ==================== Subfinder Config Types ====================

// WorkerSubfinderReq Subfinder配置获取请求
type WorkerSubfinderReq struct {
	WorkspaceId string `json:"workspaceId"`
}

// WorkerSubfinderProvider Subfinder数据源
type WorkerSubfinderProvider struct {
	Id          string   `json:"id"`
	Provider    string   `json:"provider"`
	Keys        []string `json:"keys"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
}

// WorkerSubfinderResp Subfinder配置获取响应
type WorkerSubfinderResp struct {
	Code      int                       `json:"code"`
	Msg       string                    `json:"msg"`
	Success   bool                      `json:"success"`
	Providers []WorkerSubfinderProvider `json:"providers"`
	Count     int32                     `json:"count"`
}

// ==================== HttpService Config Types ====================

// WorkerHttpServiceReq HTTP服务映射获取请求
type WorkerHttpServiceReq struct {
	EnabledOnly bool `json:"enabledOnly"`
}

// WorkerHttpServiceMapping HTTP服务映射
type WorkerHttpServiceMapping struct {
	Id          string `json:"id"`
	ServiceName string `json:"serviceName"`
	IsHttp      bool   `json:"isHttp"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// WorkerHttpServiceResp HTTP服务映射获取响应
type WorkerHttpServiceResp struct {
	Code     int                        `json:"code"`
	Msg      string                     `json:"msg"`
	Success  bool                       `json:"success"`
	Mappings []WorkerHttpServiceMapping `json:"mappings"`
	Count    int32                      `json:"count"`
}

// ==================== Templates Handler ====================

// WorkerConfigTemplatesHandler 模板配置获取接口
// POST /api/v1/worker/config/templates
func WorkerConfigTemplatesHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerTemplatesReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerTemplatesResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		var templates []string
		var count int32

		// 优先按ID获取
		if len(req.NucleiTemplateIds) > 0 || len(req.CustomPocIds) > 0 {
			rpcReq := &pb.GetTemplatesByIdsReq{
				NucleiTemplateIds: req.NucleiTemplateIds,
				CustomPocIds:      req.CustomPocIds,
			}
			rpcResp, err := svcCtx.TaskRpcClient.GetTemplatesByIds(r.Context(), rpcReq)
			if err != nil {
				logx.Errorf("[WorkerConfigTemplates] RPC GetTemplatesByIds error: %v", err)
				response.Error(w, err)
				return
			}
			templates = rpcResp.Templates
			count = rpcResp.Count
		} else {
			// 按标签获取
			rpcReq := &pb.GetTemplatesByTagsReq{
				Tags:       req.Tags,
				Severities: req.Severities,
			}
			rpcResp, err := svcCtx.TaskRpcClient.GetTemplatesByTags(r.Context(), rpcReq)
			if err != nil {
				logx.Errorf("[WorkerConfigTemplates] RPC GetTemplatesByTags error: %v", err)
				response.Error(w, err)
				return
			}
			templates = rpcResp.Templates
			count = rpcResp.Count
		}

		httpx.OkJson(w, &WorkerTemplatesResp{
			Code:      0,
			Msg:       "success",
			Success:   true,
			Templates: templates,
			Count:     count,
		})
	}
}

// ==================== Fingerprints Handler ====================

// WorkerConfigFingerprintsHandler 指纹配置获取接口
// POST /api/v1/worker/config/fingerprints
func WorkerConfigFingerprintsHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerFingerprintsReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerFingerprintsResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		rpcReq := &pb.GetCustomFingerprintsReq{
			EnabledOnly: req.EnabledOnly,
		}

		rpcResp, err := svcCtx.TaskRpcClient.GetCustomFingerprints(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerConfigFingerprints] RPC GetCustomFingerprints error: %v", err)
			response.Error(w, err)
			return
		}

		// 转换指纹数据
		fingerprints := make([]WorkerFingerprintDocument, 0, len(rpcResp.Fingerprints))
		for _, fp := range rpcResp.Fingerprints {
			fingerprints = append(fingerprints, WorkerFingerprintDocument{
				Id:        fp.Id,
				Name:      fp.Name,
				Category:  fp.Category,
				Rule:      fp.Rule,
				Source:    fp.Source,
				Headers:   fp.Headers,
				Cookies:   fp.Cookies,
				Html:      fp.Html,
				Scripts:   fp.Scripts,
				ScriptSrc: fp.ScriptSrc,
				Meta:      fp.Meta,
				Css:       fp.Css,
				Url:       fp.Url,
				IsBuiltin: fp.IsBuiltin,
				Enabled:   fp.Enabled,
			})
		}

		httpx.OkJson(w, &WorkerFingerprintsResp{
			Code:         0,
			Msg:          "success",
			Success:      true,
			Fingerprints: fingerprints,
			Count:        rpcResp.Count,
		})
	}
}

// ==================== Subfinder Handler ====================

// WorkerConfigSubfinderHandler Subfinder配置获取接口
// POST /api/v1/worker/config/subfinder
func WorkerConfigSubfinderHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerSubfinderReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerSubfinderResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		rpcReq := &pb.GetSubfinderProvidersReq{
			WorkspaceId: req.WorkspaceId,
		}

		rpcResp, err := svcCtx.TaskRpcClient.GetSubfinderProviders(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerConfigSubfinder] RPC GetSubfinderProviders error: %v", err)
			response.Error(w, err)
			return
		}

		// 转换数据源数据
		providers := make([]WorkerSubfinderProvider, 0, len(rpcResp.Providers))
		for _, p := range rpcResp.Providers {
			providers = append(providers, WorkerSubfinderProvider{
				Id:          p.Id,
				Provider:    p.Provider,
				Keys:        p.Keys,
				Status:      p.Status,
				Description: p.Description,
			})
		}

		httpx.OkJson(w, &WorkerSubfinderResp{
			Code:      0,
			Msg:       "success",
			Success:   true,
			Providers: providers,
			Count:     rpcResp.Count,
		})
	}
}

// ==================== HttpService Handler ====================

// WorkerConfigHttpServiceHandler HTTP服务映射获取接口
// POST /api/v1/worker/config/httpservice
func WorkerConfigHttpServiceHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerHttpServiceReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerHttpServiceResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		rpcReq := &pb.GetHttpServiceMappingsReq{
			EnabledOnly: req.EnabledOnly,
		}

		rpcResp, err := svcCtx.TaskRpcClient.GetHttpServiceMappings(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerConfigHttpService] RPC GetHttpServiceMappings error: %v", err)
			response.Error(w, err)
			return
		}

		// 转换映射数据
		mappings := make([]WorkerHttpServiceMapping, 0, len(rpcResp.Mappings))
		for _, m := range rpcResp.Mappings {
			mappings = append(mappings, WorkerHttpServiceMapping{
				Id:          m.Id,
				ServiceName: m.ServiceName,
				IsHttp:      m.IsHttp,
				Description: m.Description,
				Enabled:     m.Enabled,
			})
		}

		httpx.OkJson(w, &WorkerHttpServiceResp{
			Code:     0,
			Msg:      "success",
			Success:  true,
			Mappings: mappings,
			Count:    rpcResp.Count,
		})
	}
}

// ==================== POC Config Types ====================

// WorkerPocReq POC获取请求
type WorkerPocReq struct {
	PocId   string `json:"pocId"`
	PocType string `json:"pocType"` // nuclei, custom
}

// WorkerPocResp POC获取响应
type WorkerPocResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
	Content string `json:"content"`
	PocId   string `json:"pocId"`
	PocType string `json:"pocType"`
}

// ==================== POC Handler ====================

// WorkerConfigPocHandler POC配置获取接口
// POST /api/v1/worker/config/poc
func WorkerConfigPocHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerPocReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerPocResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.PocId == "" {
			httpx.OkJson(w, &WorkerPocResp{Code: 400, Msg: "pocId不能为空"})
			return
		}

		rpcReq := &pb.GetPocByIdReq{
			PocId:   req.PocId,
			PocType: req.PocType,
		}

		rpcResp, err := svcCtx.TaskRpcClient.GetPocById(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerConfigPoc] RPC GetPocById error: %v", err)
			response.Error(w, err)
			return
		}

		if !rpcResp.Success {
			httpx.OkJson(w, &WorkerPocResp{
				Code:    500,
				Msg:     rpcResp.Message,
				Success: false,
			})
			return
		}

		httpx.OkJson(w, &WorkerPocResp{
			Code:    0,
			Msg:     "success",
			Success: true,
			Content: rpcResp.Content,
			PocId:   rpcResp.PocId,
			PocType: rpcResp.PocType,
		})
	}
}
