package logic

import (
	"context"
	"fmt"
	"strconv"

	"cscan/api/internal/logic/common"
	"cscan/api/internal/svc"
	"cscan/api/internal/types"
	"cscan/model"

	"go.mongodb.org/mongo-driver/bson"
)

type SiteLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewSiteLogic(ctx context.Context, svcCtx *svc.ServiceContext) *SiteLogic {
	return &SiteLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

// SiteList 站点列表 - 只返回Web资产（HTTP/HTTPS服务）
// 判断条件：is_http=true 或 service=http/https 或 有title 或 有screenshot
func (l *SiteLogic) SiteList(req *types.SiteListReq, workspaceId string) (*types.SiteListResp, error) {
	resp := &types.SiteListResp{Code: 0, List: []types.Site{}}

	workspaceIds := common.GetWorkspaceIds(l.ctx, l.svcCtx, workspaceId)
	if len(workspaceIds) == 0 {
		return resp, nil
	}

	orgMap := common.LoadOrgMap(l.ctx, l.svcCtx)

	var allSites []types.Site
	totalCount := 0

	for _, wsId := range workspaceIds {
		assetModel := model.NewAssetModel(l.svcCtx.MongoDB, wsId)

		// 构建Web资产查询条件
		// Web资产判断：is_http=true 或 service包含http 或 有title 或 有screenshot
		webFilter := bson.M{
			"$or": []bson.M{
				{"is_http": true},
				{"service": bson.M{"$in": []string{"http", "https", "http-proxy", "https-alt"}}},
				{"title": bson.M{"$exists": true, "$ne": ""}},
				{"screenshot": bson.M{"$exists": true, "$ne": ""}},
				{"port": bson.M{"$in": []int{80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000}}},
			},
		}

		// 额外搜索条件
		filter := bson.M{}
		conditions := []bson.M{webFilter}

		if req.Site != "" {
			conditions = append(conditions, bson.M{
				"$or": []bson.M{
					{"authority": bson.M{"$regex": req.Site, "$options": "i"}},
					{"host": bson.M{"$regex": req.Site, "$options": "i"}},
				},
			})
		}
		if req.Title != "" {
			conditions = append(conditions, bson.M{"title": bson.M{"$regex": req.Title, "$options": "i"}})
		}
		if req.App != "" {
			conditions = append(conditions, bson.M{"app": bson.M{"$regex": req.App, "$options": "i"}})
		}
		if req.HttpStatus != "" {
			conditions = append(conditions, bson.M{"status": req.HttpStatus})
		}
		if req.OrgId != "" {
			conditions = append(conditions, bson.M{"org_id": req.OrgId})
		}

		if len(conditions) > 1 {
			filter["$and"] = conditions
		} else {
			filter = webFilter
		}

		// 统计总数
		count, _ := assetModel.Count(l.ctx, filter)
		totalCount += int(count)

		// 查询数据
		assets, err := assetModel.Find(l.ctx, filter, req.Page, req.PageSize)
		if err != nil {
			continue
		}

		for _, asset := range assets {
			site := types.Site{
				Id:         asset.Id.Hex(),
				Title:      asset.Title,
				IP:         asset.Host,
				Port:       asset.Port,
				Service:    asset.Service,
				HttpStatus: asset.HttpStatus,
				App:        asset.App,
				Screenshot: asset.Screenshot,
				OrgId:      asset.OrgId,
				HttpHeader: asset.HttpHeader,
				IconHash:   asset.IconHash,
			}

			// 构建站点URL
			scheme := "http"
			if asset.Service == "https" || asset.Port == 443 || asset.Port == 8443 {
				scheme = "https"
			}
			if asset.Authority != "" {
				site.Site = fmt.Sprintf("%s://%s", scheme, asset.Authority)
			} else {
				site.Site = fmt.Sprintf("%s://%s:%d", scheme, asset.Host, asset.Port)
			}

			// 获取位置信息
			if len(asset.Ip.IpV4) > 0 {
				site.Location = asset.Ip.IpV4[0].Location
			}

			// 组织名称
			if asset.OrgId != "" {
				site.OrgName = orgMap[asset.OrgId]
			}

			site.UpdateTime = asset.UpdateTime.Local().Format("2006-01-02 15:04:05")
			allSites = append(allSites, site)
		}
	}

	resp.Total = totalCount
	resp.List = allSites
	return resp, nil
}

// SiteDelete 删除站点（实际删除对应的资产）
func (l *SiteLogic) SiteDelete(req *types.SiteDeleteReq, workspaceId string) (*types.BaseResp, error) {
	workspaceIds := common.GetWorkspaceIds(l.ctx, l.svcCtx, workspaceId)

	for _, wsId := range workspaceIds {
		assetModel := model.NewAssetModel(l.svcCtx.MongoDB, wsId)
		// 先检查资产是否存在
		asset, err := assetModel.FindById(l.ctx, req.Id)
		if err != nil {
			continue
		}
		if asset != nil {
			err = assetModel.Delete(l.ctx, req.Id)
			if err == nil {
				return &types.BaseResp{Code: 0, Msg: "删除成功"}, nil
			}
		}
	}

	return &types.BaseResp{Code: 500, Msg: "删除失败，资产不存在"}, nil
}

// SiteBatchDelete 批量删除站点
func (l *SiteLogic) SiteBatchDelete(req *types.SiteBatchDeleteReq, workspaceId string) (*types.BaseResp, error) {
	if len(req.Ids) == 0 {
		return &types.BaseResp{Code: 400, Msg: "请选择要删除的站点"}, nil
	}

	workspaceIds := common.GetWorkspaceIds(l.ctx, l.svcCtx, workspaceId)
	var totalDeleted int64

	for _, wsId := range workspaceIds {
		assetModel := model.NewAssetModel(l.svcCtx.MongoDB, wsId)
		deleted, _ := assetModel.BatchDelete(l.ctx, req.Ids)
		totalDeleted += deleted
	}

	if totalDeleted == 0 {
		return &types.BaseResp{Code: 500, Msg: "删除失败，未找到匹配的站点"}, nil
	}

	return &types.BaseResp{Code: 0, Msg: "成功删除 " + strconv.Itoa(int(totalDeleted)) + " 个站点"}, nil
}

// SiteStat 站点统计
func (l *SiteLogic) SiteStat(workspaceId string) (*types.SiteStatResp, error) {
	resp := &types.SiteStatResp{Code: 0}

	workspaceIds := common.GetWorkspaceIds(l.ctx, l.svcCtx, workspaceId)
	if len(workspaceIds) == 0 {
		return resp, nil
	}

	for _, wsId := range workspaceIds {
		assetModel := model.NewAssetModel(l.svcCtx.MongoDB, wsId)

		// Web资产过滤条件
		webFilter := bson.M{
			"$or": []bson.M{
				{"is_http": true},
				{"service": bson.M{"$in": []string{"http", "https"}}},
				{"title": bson.M{"$exists": true, "$ne": ""}},
				{"screenshot": bson.M{"$exists": true, "$ne": ""}},
			},
		}

		// 总数
		total, _ := assetModel.Count(l.ctx, webFilter)
		resp.Total += int(total)

		// HTTP数量
		httpCount, _ := assetModel.Count(l.ctx, bson.M{
			"$and": []bson.M{
				webFilter,
				{"$or": []bson.M{
					{"service": "http"},
					{"port": 80},
				}},
			},
		})
		resp.HttpCount += int(httpCount)

		// HTTPS数量
		httpsCount, _ := assetModel.Count(l.ctx, bson.M{
			"$and": []bson.M{
				webFilter,
				{"$or": []bson.M{
					{"service": "https"},
					{"port": 443},
				}},
			},
		})
		resp.HttpsCount += int(httpsCount)

		// 新增数量
		newCount, _ := assetModel.Count(l.ctx, bson.M{
			"$and": []bson.M{
				webFilter,
				{"new": true},
			},
		})
		resp.NewCount += int(newCount)
	}

	return resp, nil
}
