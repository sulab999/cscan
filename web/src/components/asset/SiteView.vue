<template>
  <div class="site-view">
    <!-- 搜索区域 -->
    <el-card class="search-card">
      <el-form :inline="true" class="search-form">
        <el-form-item label="站点">
          <el-input v-model="searchForm.site" placeholder="URL/域名" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="标题">
          <el-input v-model="searchForm.title" placeholder="网页标题" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="应用">
          <el-input v-model="searchForm.app" placeholder="指纹/应用" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="状态码">
          <el-input v-model="searchForm.httpStatus" placeholder="200/404..." clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="组织">
          <el-select v-model="searchForm.orgId" placeholder="全部组织" clearable style="width: 140px">
            <el-option label="全部组织" value="" />
            <el-option v-for="org in organizations" :key="org.id" :label="org.name" :value="org.id" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">搜索</el-button>
          <el-button @click="handleReset">重置</el-button>
          <el-button type="danger" plain @click="handleClear">清空数据</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 统计信息 -->
    <el-row :gutter="16" class="stat-row">
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.total }}</div>
          <div class="stat-label">站点总数</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.httpCount }}</div>
          <div class="stat-label">HTTP站点</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.httpsCount }}</div>
          <div class="stat-label">HTTPS站点</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.newCount }}</div>
          <div class="stat-label">新增站点</div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 数据表格 -->
    <el-card class="table-card">
      <div class="table-header">
        <span class="total-info">共 {{ pagination.total }} 个站点</span>
        <div class="table-actions">
          <el-button type="danger" size="small" :disabled="selectedRows.length === 0" @click="handleBatchDelete">
            批量删除 ({{ selectedRows.length }})
          </el-button>
          <el-dropdown style="margin-left: 10px" @command="handleExport">
            <el-button type="success" size="small">
              导出<el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="selected-site" :disabled="selectedRows.length === 0">导出选中站点 ({{ selectedRows.length }})</el-dropdown-item>
                <el-dropdown-item divided command="all-site">导出全部站点</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
      
      <el-table :data="tableData" v-loading="loading" stripe max-height="500" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="40" />
        <el-table-column label="站点" min-width="280">
          <template #default="{ row }">
            <div class="site-cell">
              <a :href="row.site" target="_blank" class="site-link">{{ row.site }}</a>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="标题" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ row.title || '-' }}</template>
        </el-table-column>
        <el-table-column label="状态码" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.httpStatus)" size="small">{{ row.httpStatus || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="应用指纹" min-width="180">
          <template #default="{ row }">
            <el-tag v-for="app in (row.app || []).slice(0, 3)" :key="app" size="small" type="success" style="margin: 2px">
              {{ app }}
            </el-tag>
            <span v-if="(row.app || []).length > 3" class="more-apps">+{{ (row.app || []).length - 3 }}</span>
          </template>
        </el-table-column>
        <el-table-column label="截图" width="100" align="center">
          <template #default="{ row }">
            <el-image 
              v-if="row.screenshot" 
              :src="getScreenshotUrl(row.screenshot)" 
              :preview-src-list="[getScreenshotUrl(row.screenshot)]" 
              :z-index="9999"
              :preview-teleported="true"
              :hide-on-click-modal="true"
              fit="cover" 
              class="screenshot-img" 
            />
            <span v-else>-</span>
          </template>
        </el-table-column>

        <el-table-column label="更新时间" width="160">
          <template #default="{ row }">{{ row.updateTime }}</template>
        </el-table-column>
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" link size="small" @click="showDetail(row)">详情</el-button>
            <el-button type="danger" link size="small" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.pageSize"
        :total="pagination.total"
        :page-sizes="[20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        class="pagination"
        @size-change="loadData"
        @current-change="loadData"
      />
    </el-card>

    <!-- 详情对话框 -->
    <el-dialog v-model="detailVisible" title="站点详情" width="700px">
      <el-descriptions :column="2" border v-if="currentSite">
        <el-descriptions-item label="站点地址" :span="2">
          <a :href="currentSite.site" target="_blank" class="site-link">{{ currentSite.site }}</a>
        </el-descriptions-item>
        <el-descriptions-item label="标题" :span="2">{{ currentSite.title || '-' }}</el-descriptions-item>
        <el-descriptions-item label="状态码">
          <el-tag :type="getStatusType(currentSite.httpStatus)" size="small">{{ currentSite.httpStatus || '-' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Server">{{ currentSite.server || '-' }}</el-descriptions-item>
        <el-descriptions-item label="IP">{{ currentSite.ip || '-' }}</el-descriptions-item>
        <el-descriptions-item label="位置">{{ currentSite.location || '-' }}</el-descriptions-item>
        <el-descriptions-item label="组织">{{ currentSite.orgName || '默认组织' }}</el-descriptions-item>
        <el-descriptions-item label="更新时间">{{ currentSite.updateTime }}</el-descriptions-item>
        <el-descriptions-item label="应用指纹" :span="2">
          <el-tag v-for="app in (currentSite.app || [])" :key="app" size="small" type="success" style="margin: 2px">
            {{ app }}
          </el-tag>
          <span v-if="!(currentSite.app || []).length">-</span>
        </el-descriptions-item>
        <el-descriptions-item label="截图" :span="2" v-if="currentSite.screenshot">
          <el-image 
            :src="getScreenshotUrl(currentSite.screenshot)" 
            :preview-src-list="[getScreenshotUrl(currentSite.screenshot)]"
            :z-index="9999"
            :preview-teleported="true"
            :hide-on-click-modal="true"
            fit="contain"
            style="max-width: 400px; max-height: 300px; cursor: pointer;"
          />
        </el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button @click="detailVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown } from '@element-plus/icons-vue'
import request from '@/api/request'
import { clearAsset } from '@/api/asset'

const emit = defineEmits(['data-changed'])

const loading = ref(false)
const tableData = ref([])
const selectedRows = ref([])
const organizations = ref([])
const detailVisible = ref(false)
const currentSite = ref(null)

const searchForm = reactive({ site: '', title: '', app: '', httpStatus: '', orgId: '' })
const stat = reactive({ total: 0, httpCount: 0, httpsCount: 0, newCount: 0 })
const pagination = reactive({ page: 1, pageSize: 20, total: 0 })

function handleWorkspaceChanged() { pagination.page = 1; loadData(); loadStat() }

onMounted(() => {
  loadData(); loadStat(); loadOrganizations()
  window.addEventListener('workspace-changed', handleWorkspaceChanged)
})
onUnmounted(() => { window.removeEventListener('workspace-changed', handleWorkspaceChanged) })

async function loadData() {
  loading.value = true
  try {
    const res = await request.post('/asset/site/list', {
      page: pagination.page, pageSize: pagination.pageSize,
      site: searchForm.site, title: searchForm.title, app: searchForm.app,
      httpStatus: searchForm.httpStatus, orgId: searchForm.orgId
    })
    if (res.code === 0) { tableData.value = res.list || []; pagination.total = res.total || 0 }
  } finally { loading.value = false }
}

async function loadStat() {
  try {
    const res = await request.post('/asset/site/stat', {})
    if (res.code === 0) {
      stat.total = res.total || 0
      stat.httpCount = res.httpCount || 0
      stat.httpsCount = res.httpsCount || 0
      stat.newCount = res.newCount || 0
    }
  } catch (e) { console.error(e) }
}

async function loadOrganizations() {
  try {
    const res = await request.post('/organization/list', { page: 1, pageSize: 100 })
    if (res.code === 0) organizations.value = res.list || []
  } catch (e) { console.error(e) }
}

function handleSearch() { pagination.page = 1; loadData() }
function handleReset() {
  Object.assign(searchForm, { site: '', title: '', app: '', httpStatus: '', orgId: '' })
  handleSearch()
}

function handleSelectionChange(rows) { selectedRows.value = rows }

async function handleBatchDelete() {
  if (selectedRows.value.length === 0) return
  await ElMessageBox.confirm(`确定删除选中的 ${selectedRows.value.length} 个站点吗？`, '提示', { type: 'warning' })
  const ids = selectedRows.value.map(row => row.id)
  const res = await request.post('/asset/site/batchDelete', { ids })
  if (res.code === 0) { ElMessage.success('删除成功'); selectedRows.value = []; loadData(); loadStat(); emit('data-changed') }
}

async function handleDelete(row) {
  await ElMessageBox.confirm('确定删除该站点吗？', '提示', { type: 'warning' })
  const res = await request.post('/asset/site/batchDelete', { ids: [row.id] })
  if (res.code === 0) { ElMessage.success('删除成功'); loadData(); loadStat(); emit('data-changed') }
}

function showDetail(row) {
  currentSite.value = row
  detailVisible.value = true
}

async function handleClear() {
  await ElMessageBox.confirm('确定清空所有资产数据吗？此操作不可恢复！', '警告', { type: 'error', confirmButtonText: '确定清空', cancelButtonText: '取消' })
  const res = await clearAsset()
  if (res.code === 0) { ElMessage.success(res.msg || '清空成功'); selectedRows.value = []; loadData(); loadStat(); emit('data-changed') }
  else { ElMessage.error(res.msg || '清空失败') }
}

// 导出功能
async function handleExport(command) {
  let data = []
  let filename = ''
  
  if (command === 'selected-site') {
    if (selectedRows.value.length === 0) {
      ElMessage.warning('请先选择要导出的站点')
      return
    }
    data = selectedRows.value
    filename = 'sites_selected.txt'
  } else {
    ElMessage.info('正在获取全部数据...')
    try {
      const res = await request.post('/asset/site/list', {
        ...searchForm, page: 1, pageSize: 10000
      })
      if (res.code === 0) {
        data = res.list || []
      } else {
        ElMessage.error('获取数据失败')
        return
      }
    } catch (e) {
      ElMessage.error('获取数据失败')
      return
    }
    filename = 'sites_all.txt'
  }
  
  if (data.length === 0) {
    ElMessage.warning('没有可导出的数据')
    return
  }
  
  const seen = new Set()
  const exportData = []
  for (const row of data) {
    if (row.site && !seen.has(row.site)) {
      seen.add(row.site)
      exportData.push(row.site)
    }
  }
  
  if (exportData.length === 0) {
    ElMessage.warning('没有可导出的数据')
    return
  }
  
  const blob = new Blob([exportData.join('\n')], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
  
  ElMessage.success(`成功导出 ${exportData.length} 条数据`)
}

function getStatusType(status) {
  if (!status) return 'info'
  const code = parseInt(status)
  if (code >= 200 && code < 300) return 'success'
  if (code >= 300 && code < 400) return 'warning'
  if (code >= 400) return 'danger'
  return 'info'
}

function getScreenshotUrl(screenshot) {
  if (!screenshot) return ''
  if (screenshot.startsWith('data:') || screenshot.startsWith('/9j/') || screenshot.startsWith('iVBOR')) {
    return screenshot.startsWith('data:') ? screenshot : `data:image/png;base64,${screenshot}`
  }
  return `/api/screenshot/${screenshot}`
}

function refresh() { loadData(); loadStat() }

defineExpose({ refresh })
</script>

<style lang="scss" scoped>
.site-view {
  .search-card { margin-bottom: 16px; }
  .stat-row {
    margin-bottom: 16px;
    .stat-card {
      text-align: center;
      .stat-value { font-size: 28px; font-weight: 600; color: var(--el-color-primary); }
      .stat-label { color: var(--el-text-color-secondary); margin-top: 8px; }
    }
  }
  .table-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;
    .total-info { color: var(--el-text-color-secondary); font-size: 14px; }
  }
  .site-cell .site-link { color: #409eff; text-decoration: none; font-family: monospace; &:hover { text-decoration: underline; } }
  .more-apps { color: var(--el-text-color-secondary); font-size: 12px; }
  .screenshot-img { width: 80px; height: 60px; border-radius: 4px; cursor: pointer; }
  .pagination { margin-top: 16px; justify-content: flex-end; }
}
</style>
