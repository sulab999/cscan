package logic

import (
	"fmt"
	"context"
	"strings"
	"cscan/api/internal/svc"
	"cscan/api/internal/types"
	"cscan/model"
	"cscan/onlineapi"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type OnlineAPILogic struct {
	ctx context.Context
	svc *svc.ServiceContext
}

func NewOnlineAPILogic(ctx context.Context, svc *svc.ServiceContext) *OnlineAPILogic {
	return &OnlineAPILogic{ctx: ctx, svc: svc}
}

// parseApps 解析指纹字符串，支持逗号分隔，过滤空值
func parseApps(product string) []string {
	if product == "" {
		return nil
	}
	
	var apps []string
	// 支持中英文逗号分隔
	parts := strings.FieldsFunc(product, func(r rune) bool {
		return r == ',' || r == '，' || r == ';' || r == '；'
	})
	
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			apps = append(apps, p)
		}
	}
	
	return apps
}

func (l *OnlineAPILogic) Search(req *types.OnlineSearchReq, workspaceId string) (*types.OnlineSearchResp, error) {
	// 获取API配置
	configModel := model.NewAPIConfigModel(l.svc.MongoDB, workspaceId)
	config, err := configModel.FindByPlatform(l.ctx, req.Platform)
	if err != nil {
		return &types.OnlineSearchResp{Code: 404, Msg: "未配置" + req.Platform + "的API密钥"}, nil
	}

	var results []types.OnlineSearchResult
	var total int

	switch req.Platform {
	case "fofa":
		client := onlineapi.NewFofaClient(config.Key, config.Secret)
		result, err := client.Search(l.ctx, req.Query, req.Page, req.PageSize)
		if err != nil {
			return &types.OnlineSearchResp{Code: 500, Msg: "查询失败: " + err.Error()}, nil
		}
		total = result.Size
		assets := client.ParseResults(result)
		for _, a := range assets {
			results = append(results, types.OnlineSearchResult{
				Host: a.Host, IP: a.IP, Port: a.Port, Protocol: a.Protocol,
				Domain: a.Domain, Title: a.Title, Server: a.Server,
				Country: a.Country, City: a.City, Banner: a.Banner,
				ICP: a.ICP, Product: a.Product, OS: a.OS,
			})
		}
	case "hunter":
		client := onlineapi.NewHunterClient(config.Key)
		// Hunter API page_size 最大为100
		hunterPageSize := req.PageSize
		if hunterPageSize > 100 {
			hunterPageSize = 100
		}
		result, err := client.Search(l.ctx, req.Query, req.Page, hunterPageSize, "", "")
		if err != nil {
			return &types.OnlineSearchResp{Code: 500, Msg: "查询失败: " + err.Error()}, nil
		}
		total = result.Data.Total
		for _, a := range result.Data.Arr {
			component := ""
			if len(a.Component) > 0 {
				component = a.Component[0].Name
			}
			results = append(results, types.OnlineSearchResult{
				Host: a.URL, IP: a.IP, Port: a.Port, Protocol: a.Protocol,
				Domain: a.Domain, Title: a.WebTitle, Server: component,
				Country: a.Country, City: a.City, Banner: a.Banner,
				ICP: a.Number, Product: component, OS: a.OS,
			})
		}
	case "quake":
		client := onlineapi.NewQuakeClient(config.Key)
		result, err := client.Search(l.ctx, req.Query, req.Page, req.PageSize)
		if err != nil {
			return &types.OnlineSearchResp{Code: 500, Msg: "查询失败: " + err.Error()}, nil
		}
		// 检查是否配额用尽
		if result.Data.IsExhausted {
			return &types.OnlineSearchResp{Code: 403, Msg: "Quake API 配额已用尽，无法获取更多数据"}, nil
		}
		total = result.Meta.Pagination.Total
		for _, a := range result.Data.Items {
			results = append(results, types.OnlineSearchResult{
				Host: a.Service.HTTP.Host, IP: a.IP, Port: a.Port, Protocol: a.Service.Name,
				Title: a.Service.HTTP.Title, Server: a.Service.HTTP.Server,
				Country: a.Location.CountryCN, City: a.Location.CityCN,
			})
		}
	default:
		return &types.OnlineSearchResp{Code: 400, Msg: "不支持的平台"}, nil
	}

	return &types.OnlineSearchResp{Code: 0, Msg: "success", Total: total, List: results}, nil
}


func (l *OnlineAPILogic) Import(req *types.OnlineImportReq, workspaceId string) (*types.BaseResp, error) {
	assetModel := l.svc.GetAssetModel(workspaceId)

	count := 0
	for _, a := range req.Assets {
		apps := parseApps(a.Product)
		asset := &model.Asset{
			Authority: a.Host,
			Host:      a.IP,
			Port:      a.Port,
			Service:   a.Protocol,
			Title:     a.Title,
			App:       apps,
			Source:    "onlineapi",
		}
		if err := assetModel.Upsert(l.ctx, asset); err == nil {
			count++
		}
	}

	return &types.BaseResp{Code: 0, Msg: fmt.Sprintf("成功导入%d条资产", count)}, nil
}

// ImportAll 导入全部资产（自动遍历所有页面）
func (l *OnlineAPILogic) ImportAll(req *types.OnlineImportAllReq, workspaceId string) (*types.OnlineImportAllResp, error) {
	// 获取API配置
	configModel := model.NewAPIConfigModel(l.svc.MongoDB, workspaceId)
	config, err := configModel.FindByPlatform(l.ctx, req.Platform)
	if err != nil {
		return &types.OnlineImportAllResp{Code: 404, Msg: "未配置" + req.Platform + "的API密钥"}, nil
	}

	assetModel := l.svc.GetAssetModel(workspaceId)
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	
	// Hunter 和 Quake 单次最大 100
	if req.Platform == "hunter" || req.Platform == "quake" {
		if pageSize > 100 {
			pageSize = 100
		}
	}
	
	// maxPages <= 0 表示不限制页数
	maxPages := req.MaxPages
	hasMaxPages := maxPages > 0

	totalFetched := 0
	totalImport := 0
	currentPage := 1

PageLoop:
	for {
		// 如果设置了最大页数限制，检查是否超过
		if hasMaxPages && currentPage > maxPages {
			break
		}
		
		var results []types.OnlineSearchResult

		switch req.Platform {
		case "fofa":
			client := onlineapi.NewFofaClient(config.Key, config.Secret)
			result, err := client.Search(l.ctx, req.Query, currentPage, pageSize)
			if err != nil {
				if currentPage == 1 {
					return &types.OnlineImportAllResp{Code: 500, Msg: "查询失败: " + err.Error()}, nil
				}
				break PageLoop
			}
			assets := client.ParseResults(result)
			for _, a := range assets {
				results = append(results, types.OnlineSearchResult{
					Host: a.Host, IP: a.IP, Port: a.Port, Protocol: a.Protocol,
					Domain: a.Domain, Title: a.Title, Server: a.Server,
					Country: a.Country, City: a.City, Banner: a.Banner,
					ICP: a.ICP, Product: a.Product, OS: a.OS,
				})
			}
		case "hunter":
			client := onlineapi.NewHunterClient(config.Key)
			// Hunter API page_size 最大为100
			hunterPageSize := pageSize
			if hunterPageSize > 100 {
				hunterPageSize = 100
			}
			result, err := client.Search(l.ctx, req.Query, currentPage, hunterPageSize, "", "")
			if err != nil {
				if currentPage == 1 {
					return &types.OnlineImportAllResp{Code: 500, Msg: "查询失败: " + err.Error()}, nil
				}
				break PageLoop
			}
			for _, a := range result.Data.Arr {
				component := ""
				if len(a.Component) > 0 {
					component = a.Component[0].Name
				}
				results = append(results, types.OnlineSearchResult{
					Host: a.URL, IP: a.IP, Port: a.Port, Protocol: a.Protocol,
					Domain: a.Domain, Title: a.WebTitle, Server: component,
					Country: a.Country, City: a.City, Banner: a.Banner,
					ICP: a.Number, Product: component, OS: a.OS,
				})
			}
		case "quake":
			client := onlineapi.NewQuakeClient(config.Key)
			result, err := client.Search(l.ctx, req.Query, currentPage, pageSize)
			if err != nil {
				if currentPage == 1 {
					return &types.OnlineImportAllResp{Code: 500, Msg: "查询失败: " + err.Error()}, nil
				}
				break PageLoop
			}
			// 检查是否配额用尽
			if result.Data.IsExhausted {
				break PageLoop
			}
			for _, a := range result.Data.Items {
				results = append(results, types.OnlineSearchResult{
					Host: a.Service.HTTP.Host, IP: a.IP, Port: a.Port, Protocol: a.Service.Name,
					Title: a.Service.HTTP.Title, Server: a.Service.HTTP.Server,
					Country: a.Location.CountryCN, City: a.Location.CityCN,
				})
			}
		default:
			return &types.OnlineImportAllResp{Code: 400, Msg: "不支持的平台"}, nil
		}

		// 没有更多数据了
		if len(results) == 0 {
			break
		}

		totalFetched += len(results)

		// 导入当前页的资产
		for _, a := range results {
			apps := parseApps(a.Product)
			asset := &model.Asset{
				Authority: a.Host,
				Host:      a.IP,
				Port:      a.Port,
				Service:   a.Protocol,
				Title:     a.Title,
				App:       apps,
				Source:    "onlineapi",
			}
			if err := assetModel.Upsert(l.ctx, asset); err == nil {
				totalImport++
			}
		}

		// 如果当前页返回的数据量小于 pageSize，说明已经是最后一页
		// 注意：对于 Quake，配额用尽时会返回空数组，上面已经处理
		if len(results) < pageSize {
			break
		}

		currentPage++
	}

	totalPages := currentPage
	return &types.OnlineImportAllResp{
		Code:         0,
		Msg:          fmt.Sprintf("成功导入%d条资产（共获取%d条，%d页）", totalImport, totalFetched, totalPages),
		TotalFetched: totalFetched,
		TotalImport:  totalImport,
		TotalPages:   totalPages,
	}, nil
}

func (l *OnlineAPILogic) ConfigList(workspaceId string) (*types.APIConfigListResp, error) {
	configModel := model.NewAPIConfigModel(l.svc.MongoDB, workspaceId)
	docs, err := configModel.FindAll(l.ctx)
	if err != nil {
		return &types.APIConfigListResp{Code: 500, Msg: "查询失败"}, nil
	}

	list := make([]types.APIConfig, 0, len(docs))
	for _, doc := range docs {
		list = append(list, types.APIConfig{
			Id:         doc.Id.Hex(),
			Platform:   doc.Platform,
			Key:        doc.Key,
			Secret:     maskSecret(doc.Secret),
			Status:     doc.Status,
			CreateTime: doc.CreateTime.Local().Format("2006-01-02 15:04:05"),
		})
	}

	return &types.APIConfigListResp{Code: 0, Msg: "success", List: list}, nil
}

func (l *OnlineAPILogic) ConfigSave(req *types.APIConfigSaveReq, workspaceId string) (*types.BaseResp, error) {
	configModel := model.NewAPIConfigModel(l.svc.MongoDB, workspaceId)

	if req.Id != "" {
		update := bson.M{
			"key":         req.Key,
			"secret":      req.Secret,
			"update_time": time.Now(),
		}
		if err := configModel.Update(l.ctx, req.Id, update); err != nil {
			return &types.BaseResp{Code: 500, Msg: "更新失败"}, nil
		}
	} else {
		doc := &model.APIConfig{
			Id:       primitive.NewObjectID(),
			Platform: req.Platform,
			Key:      req.Key,
			Secret:   req.Secret,
			Status:   "enable",
		}
		if err := configModel.Insert(l.ctx, doc); err != nil {
			return &types.BaseResp{Code: 500, Msg: "保存失败"}, nil
		}
	}

	return &types.BaseResp{Code: 0, Msg: "保存成功"}, nil
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
