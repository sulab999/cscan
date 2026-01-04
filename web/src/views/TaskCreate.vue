<template>
  <div class="task-create-page">
    <el-card class="create-card">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="120px" class="task-form">
        <!-- 基本信息 -->
        <el-form-item label="任务名称" prop="name">
          <el-input v-model="form.name" placeholder="请输入任务名称" />
        </el-form-item>
        <el-form-item label="扫描目标" prop="target">
          <el-input v-model="form.target" type="textarea" :rows="6" placeholder="每行一个目标，支持格式:&#10;• IP: 192.168.1.1&#10;• CIDR: 192.168.1.0/24&#10;• IP范围: 192.168.1.1-192.168.1.100&#10;• 域名: example.com" />
        </el-form-item>
        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="工作空间">
              <el-select v-model="form.workspaceId" placeholder="选择工作空间" clearable style="width: 100%">
                <el-option v-for="ws in workspaces" :key="ws.id" :label="ws.name" :value="ws.id" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="所属组织">
              <el-select v-model="form.orgId" placeholder="选择组织" clearable style="width: 100%">
                <el-option v-for="org in organizations" :key="org.id" :label="org.name" :value="org.id" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item label="指定Worker">
          <el-select v-model="form.workers" multiple placeholder="不选则任意Worker执行" clearable style="width: 100%">
            <el-option v-for="w in workers" :key="w.name" :label="`${w.name} (${w.ip})`" :value="w.name" />
          </el-select>
        </el-form-item>
        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="定时任务">
              <el-switch v-model="form.isCron" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item v-if="form.isCron" label="Cron表达式">
              <el-input v-model="form.cronRule" placeholder="0 0 * * *" />
            </el-form-item>
          </el-col>
        </el-row>

        <!-- 可折叠配置区域 -->
        <el-collapse v-model="activeCollapse" class="config-collapse">
          <!-- 子域名扫描 -->
          <el-collapse-item name="domainscan">
            <template #title>
              <span class="collapse-title">子域名扫描 <el-tag v-if="form.domainscanEnable" type="success" size="small">开</el-tag></span>
            </template>
            <el-form-item label="启用">
              <el-switch v-model="form.domainscanEnable" />
              <span class="form-hint">针对域名目标进行子域名枚举</span>
            </el-form-item>
            <template v-if="form.domainscanEnable">
              <el-form-item label="使用Subfinder">
                <el-switch v-model="form.domainscanSubfinder" />
                <span class="form-hint">使用Subfinder进行子域名枚举</span>
              </el-form-item>
              <el-row :gutter="20">
                <el-col :span="12">
                  <el-form-item label="超时时间(秒)">
                    <el-input-number v-model="form.domainscanTimeout" :min="60" :max="3600" style="width:100%" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="最大枚举时间(分)">
                    <el-input-number v-model="form.domainscanMaxEnumTime" :min="1" :max="60" style="width:100%" />
                  </el-form-item>
                </el-col>
              </el-row>
              <el-row :gutter="20">
                <el-col :span="12">
                  <el-form-item label="速率限制">
                    <el-input-number v-model="form.domainscanRateLimit" :min="0" :max="1000" style="width:100%" />
                    <span class="form-hint">0=不限制</span>
                  </el-form-item>
                </el-col>
              </el-row>
              <el-form-item label="扫描选项">
                <el-checkbox v-model="form.domainscanRemoveWildcard">移除泛解析域名</el-checkbox>
              </el-form-item>
              <el-form-item label="DNS解析">
                <el-checkbox v-model="form.domainscanResolveDNS">解析子域名DNS</el-checkbox>
                <span class="form-hint">并发数由Worker设置控制</span>
              </el-form-item>
            </template>
          </el-collapse-item>

          <!-- 端口扫描 -->
          <el-collapse-item name="portscan">
            <template #title>
              <span class="collapse-title">端口扫描 <el-tag v-if="form.portscanEnable" type="success" size="small">开</el-tag></span>
            </template>
            <el-form-item label="启用">
              <el-switch v-model="form.portscanEnable" />
            </el-form-item>
            <template v-if="form.portscanEnable">
              <el-form-item label="扫描工具">
                <el-radio-group v-model="form.portscanTool">
                  <el-radio label="naabu">Naabu (推荐)</el-radio>
                  <el-radio label="masscan">Masscan</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item label="端口范围">
                <el-select v-model="form.ports" filterable allow-create default-first-option style="width: 100%">
                  <el-option label="top100 - 常用100端口" value="top100" />
                  <el-option label="top1000 - 常用1000端口" value="top1000" />
                  <el-option label="80,443,8080,8443 - Web常用" value="80,443,8080,8443" />
                  <el-option label="1-65535 - 全端口" value="1-65535" />
                </el-select>
              </el-form-item>
              <el-row :gutter="20">
                <el-col :span="12">
                  <el-form-item label="扫描速率">
                    <el-input-number v-model="form.portscanRate" :min="100" :max="100000" style="width:100%" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="端口阈值">
                    <el-input-number v-model="form.portThreshold" :min="0" :max="65535" style="width:100%" />
                  </el-form-item>
                </el-col>
              </el-row>
              <el-row :gutter="20">
                <el-col :span="12">
                  <el-form-item v-if="form.portscanTool === 'naabu'" label="扫描类型">
                    <el-radio-group v-model="form.scanType">
                      <el-radio label="c">CONNECT</el-radio>
                      <el-radio label="s">SYN</el-radio>
                    </el-radio-group>
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="超时(秒)">
                    <el-input-number v-model="form.portscanTimeout" :min="5" :max="1200" style="width:100%" />
                  </el-form-item>
                </el-col>
              </el-row>
              <el-form-item label="高级选项">
                <el-checkbox v-model="form.skipHostDiscovery">跳过主机发现 (-Pn)</el-checkbox>
                <span class="form-hint">跳过主机存活检测，直接扫描端口</span>
              </el-form-item>
            </template>
          </el-collapse-item>

          <!-- 端口识别 -->
          <el-collapse-item name="portidentify">
            <template #title>
              <span class="collapse-title">端口识别 <el-tag v-if="form.portidentifyEnable" type="success" size="small">开</el-tag></span>
            </template>
            <el-form-item label="启用">
              <el-switch v-model="form.portidentifyEnable" />
            </el-form-item>
            <template v-if="form.portidentifyEnable">
              <el-form-item label="超时(秒)">
                <el-input-number v-model="form.portidentifyTimeout" :min="5" :max="300" />
                <span class="form-hint">单个主机超时时间</span>
              </el-form-item>
              <el-form-item label="Nmap参数">
                <el-input v-model="form.portidentifyArgs" placeholder="-sV --version-intensity 5" />
              </el-form-item>
            </template>
          </el-collapse-item>

          <!-- 指纹识别 -->
          <el-collapse-item name="fingerprint">
            <template #title>
              <span class="collapse-title">指纹识别 <el-tag v-if="form.fingerprintEnable" type="success" size="small">开</el-tag></span>
            </template>
            <el-form-item label="启用">
              <el-switch v-model="form.fingerprintEnable" />
            </el-form-item>
            <template v-if="form.fingerprintEnable">
              <el-form-item label="探测工具">
                <el-radio-group v-model="form.fingerprintTool">
                  <el-radio label="httpx">Httpx</el-radio>
                  <el-radio label="builtin">内置引擎</el-radio>
                </el-radio-group>
                <span class="form-hint">{{ form.fingerprintTool === 'httpx' ? 'Httpx已集成Wappalyzer指纹库' : '使用sdk集成Wappalyzer指纹库' }}</span>
              </el-form-item>
              <el-form-item label="附加功能">
                <el-checkbox v-model="form.fingerprintIconHash">Icon Hash</el-checkbox>
                <el-checkbox v-model="form.fingerprintCustomEngine">自定义指纹</el-checkbox>
                <el-checkbox v-model="form.fingerprintScreenshot">网页截图</el-checkbox>
              </el-form-item>
              <el-row :gutter="20">
                <el-col :span="12">
                  <el-form-item label="超时(秒)">
                    <el-input-number v-model="form.fingerprintTimeout" :min="5" :max="120" style="width:100%" />
                    <span class="form-hint">并发数由Worker设置控制</span>
                  </el-form-item>
                </el-col>
              </el-row>
            </template>
          </el-collapse-item>

          <!-- 漏洞扫描 -->
          <el-collapse-item name="pocscan">
            <template #title>
              <span class="collapse-title">漏洞扫描 <el-tag v-if="form.pocscanEnable" type="success" size="small">开</el-tag></span>
            </template>
            <el-form-item label="启用">
              <el-switch v-model="form.pocscanEnable" />
              <span class="form-hint">使用 Nuclei 引擎</span>
            </el-form-item>
            <template v-if="form.pocscanEnable">
              <el-form-item label="POC来源">
                <el-radio-group v-model="form.pocscanMode" @change="handlePocModeChange">
                  <el-radio value="auto">自动匹配</el-radio>
                  <el-radio value="manual">手动选择</el-radio>
                </el-radio-group>
              </el-form-item>
              
              <!-- 自动匹配模式 -->
              <template v-if="form.pocscanMode === 'auto'">
                <el-form-item label="自动扫描">
                  <el-checkbox v-model="form.pocscanAutoScan" :disabled="form.pocscanCustomOnly">自定义标签映射</el-checkbox>
                  <el-checkbox v-model="form.pocscanAutomaticScan" :disabled="form.pocscanCustomOnly || !form.fingerprintEnable">Web指纹自动匹配</el-checkbox>
                  <span v-if="!form.fingerprintEnable && !form.pocscanCustomOnly" class="form-hint" style="color: #e6a23c">需启用指纹识别</span>
                </el-form-item>
                <el-form-item label="自定义POC">
                  <el-checkbox v-model="form.pocscanCustomOnly">只使用自定义POC</el-checkbox>
                </el-form-item>
              </template>
              
              <!-- 手动选择模式 -->
              <template v-if="form.pocscanMode === 'manual'">
                <el-form-item label="已选POC">
                  <div class="selected-poc-summary">
                    <el-tag type="primary" size="small" v-if="form.pocscanNucleiTemplateIds.length">
                      默认模板: {{ form.pocscanNucleiTemplateIds.length }} 个
                    </el-tag>
                    <el-tag type="warning" size="small" v-if="form.pocscanCustomPocIds.length">
                      自定义POC: {{ form.pocscanCustomPocIds.length }} 个
                    </el-tag>
                    <span v-if="!form.pocscanNucleiTemplateIds.length && !form.pocscanCustomPocIds.length" style="color: #909399">
                      未选择任何POC
                    </span>
                    <el-button type="primary" link @click="showPocSelectDialog">选择POC</el-button>
                  </div>
                </el-form-item>
              </template>
              
              <el-form-item label="严重级别">
                <el-checkbox-group v-model="form.pocscanSeverity">
                  <el-checkbox label="critical">Critical</el-checkbox>
                  <el-checkbox label="high">High</el-checkbox>
                  <el-checkbox label="medium">Medium</el-checkbox>
                  <el-checkbox label="low">Low</el-checkbox>
                  <el-checkbox label="info">Info</el-checkbox>
                  <el-checkbox label="unknown">Unknown</el-checkbox>
                </el-checkbox-group>
              </el-form-item>
              <el-form-item label="目标超时">
                <el-input-number v-model="form.pocscanTargetTimeout" :min="30" :max="600" />
                <span class="form-hint">秒</span>
              </el-form-item>
            </template>
          </el-collapse-item>

          <!-- 高级设置 -->
          <el-collapse-item name="advanced">
            <template #title>
              <span class="collapse-title">高级设置</span>
            </template>
            <el-form-item label="任务拆分">
              <el-input-number v-model="form.batchSize" :min="0" :max="1000" :step="10" />
              <span class="form-hint">每批目标数量，0=不拆分</span>
            </el-form-item>
          </el-collapse-item>
        </el-collapse>

        <!-- 操作按钮 -->
        <div class="form-actions">
          <el-button type="primary" :loading="submitting" @click="handleSubmit">{{ isEdit ? '保存' : '创建任务' }}</el-button>
          <el-button @click="handleCancel">取消</el-button>
        </div>
      </el-form>
    </el-card>

    <!-- POC选择对话框 -->
    <el-dialog v-model="pocSelectDialogVisible" title="选择POC" width="1200px" @open="handlePocDialogOpen">
      <div class="poc-select-container">
        <!-- 左侧：POC列表 -->
        <div class="poc-select-left">
          <el-tabs v-model="pocSelectTab">
            <!-- 默认模板 -->
            <el-tab-pane label="默认模板" name="nuclei">
              <el-form :inline="true" class="poc-filter-form">
                <el-form-item>
                  <el-input v-model="nucleiTemplateFilter.keyword" placeholder="名称/ID" clearable style="width: 150px" @keyup.enter="loadNucleiTemplatesForSelect" />
                </el-form-item>
                <el-form-item>
                  <el-select v-model="nucleiTemplateFilter.severity" placeholder="级别" clearable style="width: 100px" @change="loadNucleiTemplatesForSelect">
                    <el-option label="Critical" value="critical" />
                    <el-option label="High" value="high" />
                    <el-option label="Medium" value="medium" />
                    <el-option label="Low" value="low" />
                    <el-option label="Info" value="info" />
                    <el-option label="Unknown" value="unknown" />
                  </el-select>
                </el-form-item>
                <el-form-item>
                  <el-input v-model="nucleiTemplateFilter.tag" placeholder="标签" clearable style="width: 120px" @keyup.enter="loadNucleiTemplatesForSelect" />
                </el-form-item>
                <el-form-item>
                  <el-button type="primary" size="small" @click="loadNucleiTemplatesForSelect">搜索</el-button>
                  <el-button type="success" size="small" @click="selectAllNucleiTemplates" :loading="selectAllNucleiLoading">选择全部</el-button>
                  <el-button type="warning" size="small" @click="deselectAllNucleiTemplates" v-if="selectedNucleiTemplateIds.length > 0">取消选择</el-button>
                </el-form-item>
              </el-form>
              <el-table 
                ref="nucleiTableRef"
                :data="nucleiTemplateList" 
                v-loading="nucleiTemplateLoading" 
                max-height="400"
                @selection-change="handleNucleiSelectionChange"
                row-key="id"
              >
                <el-table-column type="selection" width="45" :reserve-selection="true" />
                <el-table-column prop="id" label="模板ID" width="180" show-overflow-tooltip />
                <el-table-column prop="name" label="名称" min-width="150" show-overflow-tooltip />
                <el-table-column prop="severity" label="级别" width="80">
                  <template #default="{ row }">
                    <el-tag :type="getSeverityType(row.severity)" size="small">{{ row.severity }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="tags" label="标签" min-width="100">
                  <template #default="{ row }">
                    <el-tag v-for="tag in (row.tags || []).slice(0, 2)" :key="tag" size="small" style="margin-right: 3px">{{ tag }}</el-tag>
                    <span v-if="row.tags && row.tags.length > 2" style="color: #909399">+{{ row.tags.length - 2 }}</span>
                  </template>
                </el-table-column>
                <el-table-column label="操作" width="60" fixed="right">
                  <template #default="{ row }">
                    <el-button type="primary" link size="small" @click="viewPocContent(row, 'nuclei')">查看</el-button>
                  </template>
                </el-table-column>
              </el-table>
              <el-pagination
                v-model:current-page="nucleiTemplatePagination.page"
                v-model:page-size="nucleiTemplatePagination.pageSize"
                :total="nucleiTemplatePagination.total"
                :page-sizes="[50, 100, 200]"
                layout="total, sizes, prev, pager, next"
                class="poc-pagination"
                @size-change="loadNucleiTemplatesForSelect"
                @current-change="loadNucleiTemplatesForSelect"
              />
            </el-tab-pane>

            <!-- 自定义POC -->
            <el-tab-pane label="自定义POC" name="custom">
              <el-form :inline="true" class="poc-filter-form">
                <el-form-item>
                  <el-input v-model="customPocFilter.name" placeholder="名称" clearable style="width: 150px" @keyup.enter="loadCustomPocsForSelect" />
                </el-form-item>
                <el-form-item>
                  <el-select v-model="customPocFilter.severity" placeholder="级别" clearable style="width: 100px" @change="loadCustomPocsForSelect">
                    <el-option label="Critical" value="critical" />
                    <el-option label="High" value="high" />
                    <el-option label="Medium" value="medium" />
                    <el-option label="Low" value="low" />
                    <el-option label="Info" value="info" />
                    <el-option label="Unknown" value="unknown" />
                  </el-select>
                </el-form-item>
                <el-form-item>
                  <el-input v-model="customPocFilter.tag" placeholder="标签" clearable style="width: 120px" @keyup.enter="loadCustomPocsForSelect" />
                </el-form-item>
                <el-form-item>
                  <el-button type="primary" size="small" @click="loadCustomPocsForSelect">搜索</el-button>
                  <el-button type="success" size="small" @click="selectAllCustomPocs" :loading="selectAllCustomLoading">选择全部</el-button>
                  <el-button type="warning" size="small" @click="deselectAllCustomPocs" v-if="selectedCustomPocIds.length > 0">取消选择</el-button>
                </el-form-item>
              </el-form>
              <el-table 
                ref="customPocTableRef"
                :data="customPocList" 
                v-loading="customPocLoading" 
                max-height="400"
                @selection-change="handleCustomPocSelectionChange"
                row-key="id"
              >
                <el-table-column type="selection" width="45" :reserve-selection="true" />
                <el-table-column prop="name" label="名称" min-width="150" show-overflow-tooltip />
                <el-table-column prop="templateId" label="模板ID" width="150" show-overflow-tooltip />
                <el-table-column prop="severity" label="级别" width="80">
                  <template #default="{ row }">
                    <el-tag :type="getSeverityType(row.severity)" size="small">{{ row.severity }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="操作" width="60" fixed="right">
                  <template #default="{ row }">
                    <el-button type="primary" link size="small" @click="viewPocContent(row, 'custom')">查看</el-button>
                  </template>
                </el-table-column>
              </el-table>
              <el-pagination
                v-model:current-page="customPocPagination.page"
                v-model:page-size="customPocPagination.pageSize"
                :total="customPocPagination.total"
                :page-sizes="[50, 100, 200]"
                layout="total, sizes, prev, pager, next"
                class="poc-pagination"
                @size-change="loadCustomPocsForSelect"
                @current-change="loadCustomPocsForSelect"
              />
            </el-tab-pane>
          </el-tabs>
        </div>

        <!-- 右侧：已选择列表 -->
        <div class="poc-select-right">
          <div class="selected-header">
            <span>已选择 ({{ selectedNucleiTemplates.length + selectedCustomPocs.length }})</span>
            <el-button type="danger" link size="small" @click="clearAllSelections" v-if="selectedNucleiTemplates.length + selectedCustomPocs.length > 0">
              清空全部
            </el-button>
          </div>
          <div class="selected-search">
            <el-input v-model="selectedPocSearchKeyword" placeholder="搜索名称/模板ID" clearable size="small" :prefix-icon="Search" />
          </div>
          <div class="selected-list">
            <!-- 默认模板 -->
            <div v-if="filteredSelectedNucleiTemplates.length > 0" class="selected-group">
              <div class="group-header">
                <span>默认模板 ({{ filteredSelectedNucleiTemplates.length }}<template v-if="selectedPocSearchKeyword">/{{ selectedNucleiTemplates.length }}</template>)</span>
                <el-button type="danger" link size="small" @click="clearNucleiSelections">清空</el-button>
              </div>
              <div class="selected-items">
                <div v-for="item in filteredSelectedNucleiTemplates" :key="item.id" class="selected-item">
                  <span class="item-name" :title="item.name || item.id">{{ item.name || item.id }}</span>
                  <el-icon class="item-remove" @click="removeNucleiTemplate(item.id)"><Close /></el-icon>
                </div>
              </div>
            </div>
            <!-- 自定义POC -->
            <div v-if="filteredSelectedCustomPocs.length > 0" class="selected-group">
              <div class="group-header">
                <span>自定义POC ({{ filteredSelectedCustomPocs.length }}<template v-if="selectedPocSearchKeyword">/{{ selectedCustomPocs.length }}</template>)</span>
                <el-button type="danger" link size="small" @click="clearCustomPocSelections">清空</el-button>
              </div>
              <div class="selected-items">
                <div v-for="item in filteredSelectedCustomPocs" :key="item.id" class="selected-item">
                  <span class="item-name" :title="item.name">{{ item.name }}</span>
                  <el-icon class="item-remove" @click="removeCustomPoc(item.id)"><Close /></el-icon>
                </div>
              </div>
            </div>
            <!-- 空状态 -->
            <div v-if="filteredSelectedNucleiTemplates.length === 0 && filteredSelectedCustomPocs.length === 0" class="selected-empty">
              <span>{{ selectedPocSearchKeyword ? '无匹配结果' : '暂未选择POC' }}</span>
            </div>
          </div>
        </div>
      </div>

      <template #footer>
        <el-button @click="pocSelectDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="confirmPocSelection">确定</el-button>
      </template>
    </el-dialog>

    <!-- 查看POC内容对话框 -->
    <el-dialog v-model="pocContentDialogVisible" :title="pocContentTitle" width="800px">
      <el-descriptions :column="2" border size="small" style="margin-bottom: 15px">
        <el-descriptions-item label="模板ID">{{ currentViewPoc.id || currentViewPoc.templateId }}</el-descriptions-item>
        <el-descriptions-item label="名称">{{ currentViewPoc.name }}</el-descriptions-item>
        <el-descriptions-item label="严重级别">
          <el-tag :type="getSeverityType(currentViewPoc.severity)" size="small">{{ currentViewPoc.severity }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="作者">{{ currentViewPoc.author || '-' }}</el-descriptions-item>
        <el-descriptions-item label="标签" :span="2">
          <el-tag v-for="tag in (currentViewPoc.tags || [])" :key="tag" size="small" style="margin-right: 5px">{{ tag }}</el-tag>
          <span v-if="!currentViewPoc.tags || currentViewPoc.tags.length === 0">-</span>
        </el-descriptions-item>
        <el-descriptions-item label="描述" :span="2">{{ currentViewPoc.description || '-' }}</el-descriptions-item>
      </el-descriptions>
      <div class="poc-content-wrapper" v-loading="pocContentLoading">
        <el-input
          v-model="currentViewPoc.content"
          type="textarea"
          :rows="18"
          readonly
        />
      </div>
      <template #footer>
        <el-button @click="pocContentDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="copyPocContent">复制内容</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, watch, nextTick, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Close, Search } from '@element-plus/icons-vue'
import { createTask, updateTask, getTaskDetail, startTask, getWorkerList, getScanConfig, saveScanConfig } from '@/api/task'
import { getNucleiTemplateList, getCustomPocList, getNucleiTemplateDetail } from '@/api/poc'
import { useWorkspaceStore } from '@/stores/workspace'
import request from '@/api/request'

const router = useRouter()
const route = useRoute()
const workspaceStore = useWorkspaceStore()
const formRef = ref()
const submitting = ref(false)
const workspaces = ref([])
const organizations = ref([])
const workers = ref([])
const activeCollapse = ref(['portscan', 'fingerprint'])
const isEdit = ref(false)

// POC选择相关
const pocSelectDialogVisible = ref(false)
const pocSelectTab = ref('nuclei')
const nucleiTemplateList = ref([])
const customPocList = ref([])
const nucleiTemplateLoading = ref(false)
const customPocLoading = ref(false)
const selectAllNucleiLoading = ref(false)
const selectAllCustomLoading = ref(false)
// 标志位：防止选择全部或加载数据时selection-change清空数据
const isSelectingAll = ref(false)
const isLoadingData = ref(false)
// 查看POC内容相关
const pocContentDialogVisible = ref(false)
const pocContentLoading = ref(false)
const pocContentTitle = ref('POC内容')
const currentViewPoc = ref({})
const selectedNucleiTemplateIds = ref([])
const selectedCustomPocIds = ref([])
// 存储已选择的完整对象（用于显示名称）
const selectedNucleiTemplates = ref([])
const selectedCustomPocs = ref([])
const selectedPocSearchKeyword = ref('')

// 过滤后的已选择列表
const filteredSelectedNucleiTemplates = computed(() => {
  if (!selectedPocSearchKeyword.value) return selectedNucleiTemplates.value
  const keyword = selectedPocSearchKeyword.value.toLowerCase()
  return selectedNucleiTemplates.value.filter(t => 
    (t.name && t.name.toLowerCase().includes(keyword)) || 
    (t.id && t.id.toLowerCase().includes(keyword))
  )
})

const filteredSelectedCustomPocs = computed(() => {
  if (!selectedPocSearchKeyword.value) return selectedCustomPocs.value
  const keyword = selectedPocSearchKeyword.value.toLowerCase()
  return selectedCustomPocs.value.filter(p => 
    (p.name && p.name.toLowerCase().includes(keyword)) || 
    (p.templateId && p.templateId.toLowerCase().includes(keyword)) ||
    (p.id && p.id.toLowerCase().includes(keyword))
  )
})
const nucleiTemplateFilter = reactive({
  keyword: '',
  severity: '',
  category: '',
  tag: ''
})
const customPocFilter = reactive({
  name: '',
  severity: '',
  tag: ''
})
const nucleiTemplatePagination = reactive({ page: 1, pageSize: 50, total: 0 })
const customPocPagination = reactive({ page: 1, pageSize: 50, total: 0 })

const form = reactive({
  id: '',
  name: '',
  target: '',
  workspaceId: '',
  orgId: '',
  isCron: false,
  cronRule: '',
  workers: [],
  batchSize: 50,
  // 子域名扫描
  domainscanEnable: false,
  domainscanSubfinder: true,
  domainscanTimeout: 300,
  domainscanMaxEnumTime: 10,
  domainscanThreads: 10,
  domainscanRateLimit: 0,
  domainscanRemoveWildcard: true,
  domainscanResolveDNS: true,
  domainscanConcurrent: 50,
  // 端口扫描
  portscanEnable: true,
  portscanTool: 'naabu',
  portscanRate: 1000,
  ports: 'top100',
  portThreshold: 100,
  scanType: 'c',
  portscanTimeout: 60,
  skipHostDiscovery: false,
  // 端口识别
  portidentifyEnable: false,
  portidentifyTimeout: 30,
  portidentifyArgs: '',
  // 指纹识别
  fingerprintEnable: true,
  fingerprintTool: 'httpx',
  fingerprintIconHash: true,
  fingerprintCustomEngine: false,
  fingerprintScreenshot: false,
  fingerprintTimeout: 30,
  // 漏洞扫描
  pocscanEnable: false,
  pocscanMode: 'auto',
  pocscanAutoScan: true,
  pocscanAutomaticScan: true,
  pocscanCustomOnly: false,
  pocscanSeverity: ['critical', 'high', 'medium'],
  pocscanTargetTimeout: 600,
  pocscanNucleiTemplateIds: [],
  pocscanCustomPocIds: [],
  // 保存已选择的对象信息（用于显示名称）
  pocscanNucleiTemplates: [],
  pocscanCustomPocs: []
})

const rules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  target: [{ required: true, message: '请输入扫描目标', trigger: 'blur' }]
}

onMounted(async () => {
  await loadWorkspaces()
  await loadOrganizations()
  await loadWorkers()
  
  // 检查是否是编辑模式
  if (route.query.id) {
    isEdit.value = true
    await loadTaskDetail(route.query.id)
  } else {
    // 加载用户上次保存的扫描配置
    try {
      const res = await getScanConfig()
      if (res.code === 0 && res.config) {
        const config = JSON.parse(res.config)
        applyConfig(config)
      }
    } catch (e) { console.error('加载扫描配置失败:', e) }
    
    // 设置默认工作空间
    let wsId = workspaceStore.currentWorkspaceId
    if (wsId === 'all' || !wsId) {
      const defaultWs = workspaces.value.find(ws => ws.name === '默认工作空间')
      wsId = defaultWs ? defaultWs.id : (workspaces.value.length > 0 ? workspaces.value[0].id : '')
    }
    form.workspaceId = wsId
  }
})

async function loadWorkspaces() {
  try {
    const res = await request.post('/workspace/list', { page: 1, pageSize: 100 })
    if (res.code === 0) workspaces.value = res.list || []
  } catch (e) { console.error(e) }
}

async function loadOrganizations() {
  try {
    const res = await request.post('/organization/list', { page: 1, pageSize: 100 })
    if (res.code === 0) organizations.value = (res.list || []).filter(org => org.status === 'enable')
  } catch (e) { console.error(e) }
}

async function loadWorkers() {
  try {
    const res = await getWorkerList()
    const data = res.data || res
    if (data.code === 0) workers.value = (data.list || []).filter(w => w.status === 'running')
  } catch (e) { console.error(e) }
}

async function loadTaskDetail(taskId) {
  try {
    const res = await getTaskDetail({ id: taskId })
    if (res.code === 0 && res.data) {
      Object.assign(form, res.data)
      if (res.data.config) {
        const config = JSON.parse(res.data.config)
        applyConfig(config)
      }
    }
  } catch (e) { console.error(e) }
}

function applyConfig(config) {
  // 判断POC模式：如果有nucleiTemplateIds或customPocIds，则为手动模式
  const isManualMode = (config.pocscan?.nucleiTemplateIds?.length > 0) || (config.pocscan?.customPocIds?.length > 0)
  
  Object.assign(form, {
    batchSize: config.batchSize || 50,
    // 子域名扫描
    domainscanEnable: config.domainscan?.enable ?? false,
    domainscanSubfinder: config.domainscan?.subfinder ?? true,
    domainscanTimeout: config.domainscan?.timeout || 300,
    domainscanMaxEnumTime: config.domainscan?.maxEnumerationTime || 10,
    domainscanThreads: config.domainscan?.threads || 10,
    domainscanRateLimit: config.domainscan?.rateLimit || 0,
    domainscanRemoveWildcard: config.domainscan?.removeWildcard ?? true,
    domainscanResolveDNS: config.domainscan?.resolveDNS ?? true,
    domainscanConcurrent: config.domainscan?.concurrent || 50,
    // 端口扫描
    portscanEnable: config.portscan?.enable ?? true,
    portscanTool: config.portscan?.tool || 'naabu',
    portscanRate: config.portscan?.rate || 1000,
    ports: config.portscan?.ports || 'top100',
    portThreshold: config.portscan?.portThreshold || 100,
    scanType: config.portscan?.scanType || 'c',
    portscanTimeout: config.portscan?.timeout || 60,
    skipHostDiscovery: config.portscan?.skipHostDiscovery ?? false,
    // 端口识别
    portidentifyEnable: config.portidentify?.enable ?? false,
    portidentifyTimeout: config.portidentify?.timeout || 30,
    portidentifyArgs: config.portidentify?.args || '',
    // 指纹识别
    fingerprintEnable: config.fingerprint?.enable ?? true,
    fingerprintTool: config.fingerprint?.tool || (config.fingerprint?.httpx ? 'httpx' : 'builtin'),
    fingerprintIconHash: config.fingerprint?.iconHash ?? true,
    fingerprintCustomEngine: config.fingerprint?.customEngine ?? false,
    fingerprintScreenshot: config.fingerprint?.screenshot ?? false,
    fingerprintTimeout: config.fingerprint?.targetTimeout || 30,
    // 漏洞扫描
    pocscanEnable: config.pocscan?.enable ?? false,
    pocscanMode: isManualMode ? 'manual' : 'auto',
    pocscanAutoScan: config.pocscan?.autoScan ?? true,
    pocscanAutomaticScan: config.pocscan?.automaticScan ?? true,
    pocscanCustomOnly: config.pocscan?.customPocOnly ?? false,
    pocscanSeverity: config.pocscan?.severity ? config.pocscan.severity.split(',') : ['critical', 'high', 'medium'],
    pocscanTargetTimeout: config.pocscan?.targetTimeout || 600,
    pocscanNucleiTemplateIds: config.pocscan?.nucleiTemplateIds || [],
    pocscanCustomPocIds: config.pocscan?.customPocIds || []
  })
}

// 防抖保存配置
let saveConfigTimer = null
function debounceSaveConfig() {
  if (saveConfigTimer) clearTimeout(saveConfigTimer)
  saveConfigTimer = setTimeout(() => {
    const config = buildConfig()
    saveScanConfig({ config: JSON.stringify(config) }).catch(e => console.error('自动保存配置失败:', e))
  }, 500)
}

// 监听扫描配置变化，自动保存（仅在新建任务时）
// 使用 getter 函数返回配置字段的快照
watch(
  () => JSON.stringify({
    batchSize: form.batchSize,
    domainscanEnable: form.domainscanEnable,
    domainscanSubfinder: form.domainscanSubfinder,
    domainscanTimeout: form.domainscanTimeout,
    domainscanMaxEnumTime: form.domainscanMaxEnumTime,
    domainscanThreads: form.domainscanThreads,
    domainscanRateLimit: form.domainscanRateLimit,
    domainscanRemoveWildcard: form.domainscanRemoveWildcard,
    domainscanResolveDNS: form.domainscanResolveDNS,
    domainscanConcurrent: form.domainscanConcurrent,
    portscanEnable: form.portscanEnable,
    portscanTool: form.portscanTool,
    portscanRate: form.portscanRate,
    ports: form.ports,
    portThreshold: form.portThreshold,
    scanType: form.scanType,
    portscanTimeout: form.portscanTimeout,
    skipHostDiscovery: form.skipHostDiscovery,
    portidentifyEnable: form.portidentifyEnable,
    portidentifyTimeout: form.portidentifyTimeout,
    portidentifyArgs: form.portidentifyArgs,
    fingerprintEnable: form.fingerprintEnable,
    fingerprintTool: form.fingerprintTool,
    fingerprintIconHash: form.fingerprintIconHash,
    fingerprintCustomEngine: form.fingerprintCustomEngine,
    fingerprintScreenshot: form.fingerprintScreenshot,
    fingerprintTimeout: form.fingerprintTimeout,
    pocscanEnable: form.pocscanEnable,
    pocscanMode: form.pocscanMode,
    pocscanAutoScan: form.pocscanAutoScan,
    pocscanAutomaticScan: form.pocscanAutomaticScan,
    pocscanCustomOnly: form.pocscanCustomOnly,
    pocscanSeverity: form.pocscanSeverity,
    pocscanTargetTimeout: form.pocscanTargetTimeout,
    pocscanNucleiTemplateIds: form.pocscanNucleiTemplateIds,
    pocscanCustomPocIds: form.pocscanCustomPocIds
  }),
  () => {
    if (!isEdit.value) {
      debounceSaveConfig()
    }
  }
)

function buildConfig() {
  const config = {
    batchSize: form.batchSize,
    domainscan: {
      enable: form.domainscanEnable,
      subfinder: form.domainscanSubfinder,
      timeout: form.domainscanTimeout,
      maxEnumerationTime: form.domainscanMaxEnumTime,
      threads: form.domainscanThreads,
      rateLimit: form.domainscanRateLimit,
      removeWildcard: form.domainscanRemoveWildcard,
      resolveDNS: form.domainscanResolveDNS,
      concurrent: form.domainscanConcurrent
    },
    portscan: {
      enable: form.portscanEnable,
      tool: form.portscanTool,
      rate: form.portscanRate,
      ports: form.ports,
      portThreshold: form.portThreshold,
      scanType: form.scanType,
      timeout: form.portscanTimeout,
      skipHostDiscovery: form.skipHostDiscovery
    },
    portidentify: {
      enable: form.portidentifyEnable,
      timeout: form.portidentifyTimeout,
      args: form.portidentifyArgs
    },
    fingerprint: {
      enable: form.fingerprintEnable,
      tool: form.fingerprintTool,
      iconHash: form.fingerprintIconHash,
      customEngine: form.fingerprintCustomEngine,
      screenshot: form.fingerprintScreenshot,
      targetTimeout: form.fingerprintTimeout
    },
    pocscan: {
      enable: form.pocscanEnable,
      useNuclei: true,
      severity: form.pocscanSeverity.join(','),
      targetTimeout: form.pocscanTargetTimeout
    }
  }

  // 根据POC模式设置不同的配置
  if (form.pocscanMode === 'manual') {
    // 手动选择模式
    config.pocscan.nucleiTemplateIds = form.pocscanNucleiTemplateIds
    config.pocscan.customPocIds = form.pocscanCustomPocIds
    config.pocscan.autoScan = false
    config.pocscan.automaticScan = false
    config.pocscan.customPocOnly = false
  } else {
    // 自动匹配模式
    if (form.pocscanCustomOnly) {
      // 只使用自定义POC时，禁用自动扫描
      config.pocscan.autoScan = false
      config.pocscan.automaticScan = false
      config.pocscan.customPocOnly = true
    } else {
      config.pocscan.autoScan = form.pocscanAutoScan
      config.pocscan.automaticScan = form.pocscanAutomaticScan
      config.pocscan.customPocOnly = false
    }
  }

  return config
}

async function handleSubmit() {
  try {
    await formRef.value.validate()
  } catch (e) { return }

  submitting.value = true
  try {
    const config = buildConfig()
    const params = {
      name: form.name,
      target: form.target,
      workspaceId: form.workspaceId,
      orgId: form.orgId,
      isCron: form.isCron,
      cronRule: form.cronRule,
      workers: form.workers,
      config: JSON.stringify(config)
    }

    let res
    if (isEdit.value) {
      params.id = form.id
      res = await updateTask(params)
    } else {
      res = await createTask(params)
    }

    if (res.code === 0) {
      ElMessage.success(isEdit.value ? '任务更新成功' : '任务创建成功')
      if (!isEdit.value && res.id) {
        await startTask({ id: res.id })
        ElMessage.success('任务已启动')
      }
      router.push('/task')
    } else {
      ElMessage.error(res.msg || '操作失败')
    }
  } finally {
    submitting.value = false
  }
}

function handleCancel() {
  router.push('/task')
}

// POC选择相关方法
const nucleiTableRef = ref()
const customPocTableRef = ref()

function getSeverityType(severity) {
  const map = { critical: 'danger', high: 'warning', medium: '', low: 'info', info: 'success', unknown: 'info' }
  return map[severity] || 'info'
}

function handlePocModeChange(mode) {
  if (mode === 'manual' && !form.pocscanNucleiTemplateIds.length && !form.pocscanCustomPocIds.length) {
    // 切换到手动模式时，初始化选择
    selectedNucleiTemplateIds.value = []
    selectedCustomPocIds.value = []
  }
}

function showPocSelectDialog() {
  // 恢复之前的选择（ID和对象信息）
  selectedNucleiTemplateIds.value = [...form.pocscanNucleiTemplateIds]
  selectedCustomPocIds.value = [...form.pocscanCustomPocIds]
  selectedNucleiTemplates.value = [...(form.pocscanNucleiTemplates || [])]
  selectedCustomPocs.value = [...(form.pocscanCustomPocs || [])]
  // 清空搜索关键词
  selectedPocSearchKeyword.value = ''
  pocSelectDialogVisible.value = true
}

async function handlePocDialogOpen() {
  // 加载当前页数据
  await Promise.all([loadNucleiTemplatesForSelect(), loadCustomPocsForSelect()])
  // 等待DOM更新后恢复选中状态
  await nextTick()
  restoreTableSelections()
}

function restoreTableSelections() {
  // 恢复Nuclei模板选中状态
  if (nucleiTableRef.value && nucleiTemplateList.value.length > 0) {
    const selectedIds = new Set(selectedNucleiTemplateIds.value)
    nucleiTemplateList.value.forEach(row => {
      if (selectedIds.has(row.id)) {
        nucleiTableRef.value.toggleRowSelection(row, true)
      }
    })
  }
  // 恢复自定义POC选中状态
  if (customPocTableRef.value && customPocList.value.length > 0) {
    const selectedIds = new Set(selectedCustomPocIds.value)
    customPocList.value.forEach(row => {
      if (selectedIds.has(row.id)) {
        customPocTableRef.value.toggleRowSelection(row, true)
      }
    })
  }
}

async function loadNucleiTemplatesForSelect() {
  nucleiTemplateLoading.value = true
  isLoadingData.value = true
  try {
    const res = await getNucleiTemplateList({
      page: nucleiTemplatePagination.page,
      pageSize: nucleiTemplatePagination.pageSize,
      keyword: nucleiTemplateFilter.keyword,
      severity: nucleiTemplateFilter.severity,
      category: nucleiTemplateFilter.category,
      tag: nucleiTemplateFilter.tag
    })
    if (res.code === 0) {
      nucleiTemplateList.value = res.list || []
      nucleiTemplatePagination.total = res.total || 0
      // 等待DOM更新后恢复当前页的选中状态
      await nextTick()
      restoreNucleiTableSelection()
    }
  } catch (e) {
    console.error('加载Nuclei模板失败:', e)
  } finally {
    nucleiTemplateLoading.value = false
    // 延迟重置标志位，确保selection-change事件处理完成
    setTimeout(() => { isLoadingData.value = false }, 100)
  }
}

// 恢复Nuclei表格选中状态
function restoreNucleiTableSelection() {
  if (!nucleiTableRef.value) return
  const selectedIds = new Set(selectedNucleiTemplateIds.value)
  nucleiTemplateList.value.forEach(row => {
    if (selectedIds.has(row.id)) {
      nucleiTableRef.value.toggleRowSelection(row, true)
    }
  })
}

async function loadCustomPocsForSelect() {
  customPocLoading.value = true
  isLoadingData.value = true
  try {
    const res = await getCustomPocList({
      page: customPocPagination.page,
      pageSize: customPocPagination.pageSize,
      name: customPocFilter.name,
      severity: customPocFilter.severity,
      tag: customPocFilter.tag,
      enabled: true // 只显示启用的POC
    })
    if (res.code === 0) {
      customPocList.value = res.list || []
      customPocPagination.total = res.total || 0
      // 等待DOM更新后恢复当前页的选中状态
      await nextTick()
      restoreCustomPocTableSelection()
    }
  } catch (e) {
    console.error('加载自定义POC失败:', e)
  } finally {
    customPocLoading.value = false
    // 延迟重置标志位，确保selection-change事件处理完成
    setTimeout(() => { isLoadingData.value = false }, 100)
  }
}

// 恢复自定义POC表格选中状态
function restoreCustomPocTableSelection() {
  if (!customPocTableRef.value) return
  const selectedIds = new Set(selectedCustomPocIds.value)
  customPocList.value.forEach(row => {
    if (selectedIds.has(row.id)) {
      customPocTableRef.value.toggleRowSelection(row, true)
    }
  })
}

function handleNucleiSelectionChange(selection) {
  // 如果正在执行"选择全部"或加载数据操作，跳过处理
  if (isSelectingAll.value || isLoadingData.value) return
  
  // 获取当前页的所有ID
  const currentPageIds = new Set(nucleiTemplateList.value.map(t => t.id))
  // 获取当前页选中的ID和对象
  const currentPageSelectedIds = new Set(selection.map(t => t.id))
  const currentPageSelectedItems = selection.filter(t => currentPageIds.has(t.id))
  
  // 保留其他页的选择ID
  const newSelectedIds = selectedNucleiTemplateIds.value.filter(id => !currentPageIds.has(id))
  currentPageSelectedIds.forEach(id => newSelectedIds.push(id))
  selectedNucleiTemplateIds.value = newSelectedIds
  
  // 保留其他页的选择对象，添加当前页选中的对象
  const otherPageItems = selectedNucleiTemplates.value.filter(t => !currentPageIds.has(t.id))
  selectedNucleiTemplates.value = [...otherPageItems, ...currentPageSelectedItems]
}

function handleCustomPocSelectionChange(selection) {
  // 如果正在执行"选择全部"或加载数据操作，跳过处理
  if (isSelectingAll.value || isLoadingData.value) return
  
  // 获取当前页的所有ID
  const currentPageIds = new Set(customPocList.value.map(p => p.id))
  // 获取当前页选中的ID和对象
  const currentPageSelectedIds = new Set(selection.map(p => p.id))
  const currentPageSelectedItems = selection.filter(p => currentPageIds.has(p.id))
  
  // 保留其他页的选择ID
  const newSelectedIds = selectedCustomPocIds.value.filter(id => !currentPageIds.has(id))
  currentPageSelectedIds.forEach(id => newSelectedIds.push(id))
  selectedCustomPocIds.value = newSelectedIds
  
  // 保留其他页的选择对象，添加当前页选中的对象
  const otherPageItems = selectedCustomPocs.value.filter(p => !currentPageIds.has(p.id))
  selectedCustomPocs.value = [...otherPageItems, ...currentPageSelectedItems]
}

function confirmPocSelection() {
  form.pocscanNucleiTemplateIds = [...selectedNucleiTemplateIds.value]
  form.pocscanCustomPocIds = [...selectedCustomPocIds.value]
  // 保存对象信息用于下次打开时显示
  form.pocscanNucleiTemplates = [...selectedNucleiTemplates.value]
  form.pocscanCustomPocs = [...selectedCustomPocs.value]
  pocSelectDialogVisible.value = false
}

// 清除所有选择
function clearAllSelections() {
  selectedNucleiTemplateIds.value = []
  selectedNucleiTemplates.value = []
  selectedCustomPocIds.value = []
  selectedCustomPocs.value = []
  // 清空表格选择状态
  if (nucleiTableRef.value) {
    nucleiTableRef.value.clearSelection()
  }
  if (customPocTableRef.value) {
    customPocTableRef.value.clearSelection()
  }
}

// 选择全部Nuclei模板（根据当前筛选条件）
async function selectAllNucleiTemplates() {
  selectAllNucleiLoading.value = true
  isSelectingAll.value = true
  try {
    // 先获取总数
    const firstRes = await getNucleiTemplateList({
      page: 1,
      pageSize: 1,
      keyword: nucleiTemplateFilter.keyword,
      severity: nucleiTemplateFilter.severity,
      category: nucleiTemplateFilter.category,
      tag: nucleiTemplateFilter.tag
    })
    if (firstRes.code !== 0) {
      throw new Error(firstRes.msg || '获取数据失败')
    }
    
    const total = firstRes.total || 0
    if (total === 0) {
      ElMessage.warning('没有符合条件的模板')
      return
    }
    
    // 分页获取所有数据
    const pageSize = 5000
    const totalPages = Math.ceil(total / pageSize)
    const allTemplates = []
    
    for (let page = 1; page <= totalPages; page++) {
      const res = await getNucleiTemplateList({
        page,
        pageSize,
        keyword: nucleiTemplateFilter.keyword,
        severity: nucleiTemplateFilter.severity,
        category: nucleiTemplateFilter.category,
        tag: nucleiTemplateFilter.tag
      })
      if (res.code === 0 && res.list) {
        allTemplates.push(...res.list)
      }
    }
    
    // 合并到已选择列表（去重）
    const existingIds = new Set(selectedNucleiTemplateIds.value)
    let addedCount = 0
    allTemplates.forEach(t => {
      if (!existingIds.has(t.id)) {
        selectedNucleiTemplateIds.value.push(t.id)
        selectedNucleiTemplates.value.push({ id: t.id, name: t.name })
        addedCount++
      }
    })
    
    // 更新当前页表格选中状态
    await nextTick()
    if (nucleiTableRef.value) {
      nucleiTemplateList.value.forEach(row => {
        nucleiTableRef.value.toggleRowSelection(row, true)
      })
    }
    ElMessage.success(`已选择 ${allTemplates.length} 个模板${addedCount < allTemplates.length ? `（新增 ${addedCount} 个）` : ''}`)
  } catch (e) {
    console.error('选择全部失败:', e)
    ElMessage.error('选择全部失败')
  } finally {
    selectAllNucleiLoading.value = false
    isSelectingAll.value = false
  }
}

// 选择全部自定义POC（根据当前筛选条件）
async function selectAllCustomPocs() {
  selectAllCustomLoading.value = true
  isSelectingAll.value = true
  try {
    // 先获取总数
    const firstRes = await getCustomPocList({
      page: 1,
      pageSize: 1,
      name: customPocFilter.name,
      severity: customPocFilter.severity,
      tag: customPocFilter.tag,
      enabled: true
    })
    if (firstRes.code !== 0) {
      throw new Error(firstRes.msg || '获取数据失败')
    }
    
    const total = firstRes.total || 0
    if (total === 0) {
      ElMessage.warning('没有符合条件的POC')
      return
    }
    
    // 分页获取所有数据
    const pageSize = 5000
    const totalPages = Math.ceil(total / pageSize)
    const allPocs = []
    
    for (let page = 1; page <= totalPages; page++) {
      const res = await getCustomPocList({
        page,
        pageSize,
        name: customPocFilter.name,
        severity: customPocFilter.severity,
        tag: customPocFilter.tag,
        enabled: true
      })
      if (res.code === 0 && res.list) {
        allPocs.push(...res.list)
      }
    }
    
    // 合并到已选择列表（去重）
    const existingIds = new Set(selectedCustomPocIds.value)
    let addedCount = 0
    allPocs.forEach(p => {
      if (!existingIds.has(p.id)) {
        selectedCustomPocIds.value.push(p.id)
        selectedCustomPocs.value.push({ id: p.id, name: p.name, templateId: p.templateId })
        addedCount++
      }
    })
    
    // 更新当前页表格选中状态
    await nextTick()
    if (customPocTableRef.value) {
      customPocList.value.forEach(row => {
        customPocTableRef.value.toggleRowSelection(row, true)
      })
    }
    ElMessage.success(`已选择 ${allPocs.length} 个POC${addedCount < allPocs.length ? `（新增 ${addedCount} 个）` : ''}`)
  } catch (e) {
    console.error('选择全部失败:', e)
    ElMessage.error('选择全部失败')
  } finally {
    selectAllCustomLoading.value = false
    isSelectingAll.value = false
  }
}

// 清除Nuclei模板选择
function clearNucleiSelections() {
  selectedNucleiTemplateIds.value = []
  selectedNucleiTemplates.value = []
  if (nucleiTableRef.value) {
    nucleiTableRef.value.clearSelection()
  }
}

// 取消选择全部Nuclei模板（按钮调用）
function deselectAllNucleiTemplates() {
  clearNucleiSelections()
  ElMessage.success('已取消所有模板选择')
}

// 清除自定义POC选择
function clearCustomPocSelections() {
  selectedCustomPocIds.value = []
  selectedCustomPocs.value = []
  if (customPocTableRef.value) {
    customPocTableRef.value.clearSelection()
  }
}

// 取消选择全部自定义POC（按钮调用）
function deselectAllCustomPocs() {
  clearCustomPocSelections()
  ElMessage.success('已取消所有POC选择')
}

// 移除单个Nuclei模板
function removeNucleiTemplate(id) {
  selectedNucleiTemplateIds.value = selectedNucleiTemplateIds.value.filter(i => i !== id)
  selectedNucleiTemplates.value = selectedNucleiTemplates.value.filter(t => t.id !== id)
  // 更新表格选择状态
  if (nucleiTableRef.value) {
    const row = nucleiTemplateList.value.find(t => t.id === id)
    if (row) {
      nucleiTableRef.value.toggleRowSelection(row, false)
    }
  }
}

// 移除单个自定义POC
function removeCustomPoc(id) {
  selectedCustomPocIds.value = selectedCustomPocIds.value.filter(i => i !== id)
  selectedCustomPocs.value = selectedCustomPocs.value.filter(p => p.id !== id)
  // 更新表格选择状态
  if (customPocTableRef.value) {
    const row = customPocList.value.find(p => p.id === id)
    if (row) {
      customPocTableRef.value.toggleRowSelection(row, false)
    }
  }
}

// 查看POC内容
async function viewPocContent(row, type) {
  currentViewPoc.value = { ...row }
  pocContentTitle.value = type === 'nuclei' ? '默认模板内容' : '自定义POC内容'
  pocContentDialogVisible.value = true
  
  // 如果没有content字段，需要从后端获取
  if (!row.content) {
    pocContentLoading.value = true
    try {
      if (type === 'nuclei') {
        // 后端API需要templateId参数（模板字符串ID，如CVE-2021-xxxx）
        const res = await getNucleiTemplateDetail({ templateId: row.id })
        if (res.code === 0 && res.data) {
          currentViewPoc.value = { ...currentViewPoc.value, ...res.data }
        } else {
          currentViewPoc.value.content = res.msg || '获取内容失败'
        }
      } else {
        // 自定义POC通常在列表中已包含content
        currentViewPoc.value.content = row.content || '暂无内容'
      }
    } catch (e) {
      console.error('获取POC内容失败:', e)
      currentViewPoc.value.content = '获取内容失败'
    } finally {
      pocContentLoading.value = false
    }
  }
}

// 复制POC内容
function copyPocContent() {
  if (currentViewPoc.value.content) {
    navigator.clipboard.writeText(currentViewPoc.value.content).then(() => {
      ElMessage.success('已复制到剪贴板')
    }).catch(() => {
      ElMessage.error('复制失败')
    })
  }
}
</script>

<style lang="scss" scoped>
.task-create-page {
  .create-card {
    .task-form {
      padding: 20px 40px;
    }
  }

  .config-collapse {
    margin: 20px 0;

    :deep(.el-collapse-item__header) {
      background: var(--el-fill-color-light);
      padding: 0 16px;
      font-size: 14px;
      font-weight: 500;
      height: 44px;
      line-height: 44px;

      &:hover {
        background: var(--el-fill-color);
      }
    }

    :deep(.el-collapse-item__wrap) {
      border: none;
    }

    :deep(.el-collapse-item__content) {
      padding: 20px 16px;
    }

    .collapse-title {
      display: flex;
      align-items: center;
      gap: 10px;
    }
  }

  .form-hint {
    margin-left: 10px;
    color: var(--el-text-color-secondary);
    font-size: 12px;
  }

  .form-actions {
    margin-top: 30px;
    padding-top: 20px;
    border-top: 1px solid var(--el-border-color-lighter);

    .el-button {
      min-width: 100px;
    }
  }

  .selected-poc-summary {
    display: flex;
    align-items: center;
    gap: 10px;
  }
}

.poc-filter-form {
  margin-bottom: 10px;
}

.poc-pagination {
  margin-top: 15px;
}

.poc-select-container {
  display: flex;
  gap: 20px;
  min-height: 500px;
}

.poc-select-left {
  flex: 1;
  min-width: 0;
}

.poc-select-right {
  width: 280px;
  border: 1px solid var(--el-border-color-light);
  border-radius: 4px;
  display: flex;
  flex-direction: column;
}

.selected-header {
  padding: 12px 15px;
  border-bottom: 1px solid var(--el-border-color-light);
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 500;
  background: var(--el-fill-color-light);
}

.selected-search {
  padding: 10px;
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.selected-list {
  flex: 1;
  overflow-y: auto;
  padding: 10px;
}

.selected-group {
  margin-bottom: 15px;
  
  &:last-child {
    margin-bottom: 0;
  }
}

.group-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 5px 0;
  font-size: 13px;
  color: var(--el-text-color-secondary);
  border-bottom: 1px dashed var(--el-border-color-lighter);
  margin-bottom: 8px;
}

.selected-items {
  max-height: 180px;
  overflow-y: auto;
}

.selected-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 6px 8px;
  margin-bottom: 4px;
  background: var(--el-fill-color-light);
  border-radius: 4px;
  font-size: 12px;
  
  &:hover {
    background: var(--el-fill-color);
  }
  
  &:last-child {
    margin-bottom: 0;
  }
}

.item-name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-right: 8px;
}

.item-remove {
  cursor: pointer;
  color: var(--el-text-color-secondary);
  flex-shrink: 0;
  
  &:hover {
    color: var(--el-color-danger);
  }
}

.selected-empty {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100px;
  color: var(--el-text-color-placeholder);
  font-size: 13px;
}

.poc-content-wrapper {
  :deep(.el-textarea__inner) {
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
    font-size: 13px;
    line-height: 1.5;
    background: var(--el-fill-color-light);
    resize: none;
  }
}
</style>
