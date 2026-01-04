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

// ==================== Result Types ====================

// WorkerIPV4 IPv4信息
type WorkerIPV4 struct {
	IP       string `json:"ip"`
	IPInt    uint32 `json:"ipInt"`
	Location string `json:"location"`
}

// WorkerIPV6 IPv6信息
type WorkerIPV6 struct {
	IP       string `json:"ip"`
	Location string `json:"location"`
}

// WorkerAssetDocument 资产文档
type WorkerAssetDocument struct {
	Authority  string       `json:"authority"`
	Host       string       `json:"host"`
	Port       int32        `json:"port"`
	Category   string       `json:"category"`
	Service    string       `json:"service"`
	Server     string       `json:"server"`
	Banner     string       `json:"banner"`
	Title      string       `json:"title"`
	App        []string     `json:"app"`
	HttpStatus string       `json:"httpStatus"`
	HttpHeader string       `json:"httpHeader"`
	HttpBody   string       `json:"httpBody"`
	Cert       string       `json:"cert"`
	IconHash   string       `json:"iconHash"`
	IsCdn      bool         `json:"isCdn"`
	Cname      string       `json:"cname"`
	IsCloud    bool         `json:"isCloud"`
	Ipv4       []WorkerIPV4 `json:"ipv4"`
	Ipv6       []WorkerIPV6 `json:"ipv6"`
	Screenshot string       `json:"screenshot"`
	IsHttp     bool         `json:"isHttp"`
	Source     string       `json:"source"`
	IconData   []byte       `json:"iconData"`
}

// WorkerTaskResultReq 资产结果上报请求
type WorkerTaskResultReq struct {
	WorkspaceId string                `json:"workspaceId"`
	MainTaskId  string                `json:"mainTaskId"`
	OrgId       string                `json:"orgId"`
	Assets      []WorkerAssetDocument `json:"assets"`
}

// WorkerTaskResultResp 资产结果上报响应
type WorkerTaskResultResp struct {
	Code        int    `json:"code"`
	Msg         string `json:"msg"`
	Success     bool   `json:"success"`
	TotalAsset  int32  `json:"totalAsset"`
	NewAsset    int32  `json:"newAsset"`
	UpdateAsset int32  `json:"updateAsset"`
}

// WorkerVulDocument 漏洞文档
type WorkerVulDocument struct {
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

// WorkerVulResultReq 漏洞结果上报请求
type WorkerVulResultReq struct {
	WorkspaceId string              `json:"workspaceId"`
	MainTaskId  string              `json:"mainTaskId"`
	Vuls        []WorkerVulDocument `json:"vuls"`
}

// WorkerVulResultResp 漏洞结果上报响应
type WorkerVulResultResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
	Total   int32  `json:"total"`
}

// ==================== Task Result Handler ====================

// WorkerTaskResultHandler 资产结果上报接口
// POST /api/v1/worker/task/result
func WorkerTaskResultHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerTaskResultReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerTaskResultResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.WorkspaceId == "" || req.MainTaskId == "" {
			httpx.OkJson(w, &WorkerTaskResultResp{Code: 400, Msg: "workspaceId和mainTaskId不能为空"})
			return
		}

		// 转换资产数据为RPC格式
		pbAssets := make([]*pb.AssetDocument, 0, len(req.Assets))
		for _, asset := range req.Assets {
			pbAsset := &pb.AssetDocument{
				Authority:  asset.Authority,
				Host:       asset.Host,
				Port:       asset.Port,
				Category:   asset.Category,
				Service:    asset.Service,
				Server:     asset.Server,
				Banner:     asset.Banner,
				Title:      asset.Title,
				App:        asset.App,
				HttpStatus: asset.HttpStatus,
				HttpHeader: asset.HttpHeader,
				HttpBody:   asset.HttpBody,
				Cert:       asset.Cert,
				IconHash:   asset.IconHash,
				IsCdn:      asset.IsCdn,
				Cname:      asset.Cname,
				IsCloud:    asset.IsCloud,
				Screenshot: asset.Screenshot,
				IsHttp:     asset.IsHttp,
				Source:     asset.Source,
				IconData:   asset.IconData,
			}

			// 转换IPv4
			for _, ipv4 := range asset.Ipv4 {
				pbAsset.Ipv4 = append(pbAsset.Ipv4, &pb.IPV4{
					Ip:       ipv4.IP,
					IpInt:    ipv4.IPInt,
					Location: ipv4.Location,
				})
			}

			// 转换IPv6
			for _, ipv6 := range asset.Ipv6 {
				pbAsset.Ipv6 = append(pbAsset.Ipv6, &pb.IPV6{
					Ip:       ipv6.IP,
					Location: ipv6.Location,
				})
			}

			pbAssets = append(pbAssets, pbAsset)
		}

		// 调用RPC SaveTaskResult
		rpcReq := &pb.SaveTaskResultReq{
			WorkspaceId: req.WorkspaceId,
			MainTaskId:  req.MainTaskId,
			OrgId:       req.OrgId,
			Assets:      pbAssets,
		}

		rpcResp, err := svcCtx.TaskRpcClient.SaveTaskResult(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerTaskResult] RPC SaveTaskResult error: %v", err)
			response.Error(w, err)
			return
		}

		httpx.OkJson(w, &WorkerTaskResultResp{
			Code:        0,
			Msg:         rpcResp.Message,
			Success:     rpcResp.Success,
			TotalAsset:  rpcResp.TotalAsset,
			NewAsset:    rpcResp.NewAsset,
			UpdateAsset: rpcResp.UpdateAsset,
		})
	}
}

// ==================== Vul Result Handler ====================

// WorkerVulResultHandler 漏洞结果上报接口
// POST /api/v1/worker/task/vul
func WorkerVulResultHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerVulResultReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerVulResultResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.WorkspaceId == "" || req.MainTaskId == "" {
			httpx.OkJson(w, &WorkerVulResultResp{Code: 400, Msg: "workspaceId和mainTaskId不能为空"})
			return
		}

		// 转换漏洞数据为RPC格式
		pbVuls := make([]*pb.VulDocument, 0, len(req.Vuls))
		for _, vul := range req.Vuls {
			pbVul := &pb.VulDocument{
				Authority:        vul.Authority,
				Host:             vul.Host,
				Port:             vul.Port,
				Url:              vul.Url,
				PocFile:          vul.PocFile,
				Source:           vul.Source,
				Severity:         vul.Severity,
				Extra:            vul.Extra,
				Result:           vul.Result,
				TaskId:           vul.TaskId,
				References:       vul.References,
				ExtractedResults: vul.ExtractedResults,
			}

			// 处理可选字段
			if vul.CvssScore != nil {
				pbVul.CvssScore = vul.CvssScore
			}
			if vul.CveId != nil {
				pbVul.CveId = vul.CveId
			}
			if vul.CweId != nil {
				pbVul.CweId = vul.CweId
			}
			if vul.Remediation != nil {
				pbVul.Remediation = vul.Remediation
			}
			if vul.MatcherName != nil {
				pbVul.MatcherName = vul.MatcherName
			}
			if vul.CurlCommand != nil {
				pbVul.CurlCommand = vul.CurlCommand
			}
			if vul.Request != nil {
				pbVul.Request = vul.Request
			}
			if vul.Response != nil {
				pbVul.Response = vul.Response
			}
			if vul.ResponseTruncated != nil {
				pbVul.ResponseTruncated = vul.ResponseTruncated
			}

			pbVuls = append(pbVuls, pbVul)
		}

		// 调用RPC SaveVulResult
		rpcReq := &pb.SaveVulResultReq{
			WorkspaceId: req.WorkspaceId,
			MainTaskId:  req.MainTaskId,
			Vuls:        pbVuls,
		}

		rpcResp, err := svcCtx.TaskRpcClient.SaveVulResult(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerVulResult] RPC SaveVulResult error: %v", err)
			response.Error(w, err)
			return
		}

		httpx.OkJson(w, &WorkerVulResultResp{
			Code:    0,
			Msg:     rpcResp.Message,
			Success: rpcResp.Success,
			Total:   rpcResp.Total,
		})
	}
}
