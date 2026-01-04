<template>
  <div class="ip-view">
    <!-- 搜索区域 -->
    <el-card class="search-card">
      <el-form :inline="true" class="search-form">
        <el-form-item label="IP">
          <el-input v-model="searchForm.ip" placeholder="IP地址" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input v-model="searchForm.port" placeholder="端口号" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="服务">
          <el-input v-model="searchForm.service" placeholder="服务类型" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="地区">
          <el-input v-model="searchForm.location" placeholder="地理位置" clearable @keyup.enter="handleSearch" />
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
          <div class="stat-label">IP总数</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.portCount }}</div>
          <div class="stat-label">开放端口</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.serviceCount }}</div>
          <div class="stat-label">服务类型</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.newCount }}</div>
          <div class="stat-label">新增IP</div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 数据表格 -->
    <el-card class="table-card">
      <div class="table-header">
        <span class="total-info">共 {{ pagination.total }} 个IP</span>
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
                <el-dropdown-item command="selected-ip" :disabled="selectedRows.length === 0">导出选中IP ({{ selectedRows.length }})</el-dropdown-item>
                <el-dropdown-item divided command="all-ip">导出全部IP</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
      
      <el-table :data="tableData" v-loading="loading" stripe max-height="500" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="40" />
        <el-table-column label="IP地址" width="180">
          <template #default="{ row }">
            <div class="ip-cell">
              <span class="ip-text">{{ row.ip }}</span>
              <el-tag v-if="row.isNew" type="success" size="small" effect="dark" class="new-tag">新</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="地理位置" width="200">
          <template #default="{ row }">{{ row.location || '-' }}</template>
        </el-table-column>
        <el-table-column label="开放端口" min-width="300">
          <template #default="{ row }">
            <div class="port-list">
              <el-tag v-for="port in (row.ports || []).slice(0, 10)" :key="port.port" size="small" :type="getPortType(port.service)" class="port-tag">
                {{ port.port }}<span v-if="port.service">/{{ port.service }}</span>
              </el-tag>
              <span v-if="(row.ports || []).length > 10" class="more-ports">+{{ (row.ports || []).length - 10 }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="关联域名" min-width="200">
          <template #default="{ row }">
            <div v-if="row.domains && row.domains.length > 0" class="domain-list">
              <div v-for="domain in row.domains.slice(0, 5)" :key="domain" class="domain-item">{{ domain }}</div>
              <div v-if="row.domains.length > 5" class="more-domains">+{{ row.domains.length - 5 }} 更多...</div>
            </div>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="组织" width="120">
          <template #default="{ row }">{{ row.orgName || '默认组织' }}</template>
        </el-table-column>
        <el-table-column label="更新时间" width="160">
          <template #default="{ row }">{{ row.updateTime }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
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
    <el-dialog v-model="detailVisible" title="IP详情" width="700px">
      <el-descriptions v-if="currentIP" :column="2" border>
        <el-descriptions-item label="IP地址">{{ currentIP.ip }}</el-descriptions-item>
        <el-descriptions-item label="地理位置">{{ currentIP.location || '-' }}</el-descriptions-item>
        <el-descriptions-item label="开放端口" :span="2">
          <div class="detail-ports">
            <el-tag v-for="port in (currentIP.ports || [])" :key="port.port" size="small" style="margin: 2px">
              {{ port.port }}<span v-if="port.service">/{{ port.service }}</span>
            </el-tag>
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="关联域名" :span="2">
          <div v-if="currentIP.domains && currentIP.domains.length > 0">
            <el-tag v-for="domain in currentIP.domains" :key="domain" type="info" size="small" style="margin: 2px">{{ domain }}</el-tag>
          </div>
          <span v-else>-</span>
        </el-descriptions-item>
      </el-descriptions>
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
const currentIP = ref(null)

const searchForm = reactive({ ip: '', port: '', service: '', location: '', orgId: '' })
const stat = reactive({ total: 0, portCount: 0, serviceCount: 0, newCount: 0 })
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
    const res = await request.post('/asset/ip/list', {
      page: pagination.page, pageSize: pagination.pageSize,
      ip: searchForm.ip, port: searchForm.port, service: searchForm.service,
      location: searchForm.location, orgId: searchForm.orgId
    })
    if (res.code === 0) { tableData.value = res.list || []; pagination.total = res.total || 0 }
  } finally { loading.value = false }
}

async function loadStat() {
  try {
    const res = await request.post('/asset/ip/stat', {})
    if (res.code === 0) {
      stat.total = res.total || 0
      stat.portCount = res.portCount || 0
      stat.serviceCount = res.serviceCount || 0
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
  Object.assign(searchForm, { ip: '', port: '', service: '', location: '', orgId: '' })
  handleSearch()
}

function handleSelectionChange(rows) { selectedRows.value = rows }

function showDetail(row) { currentIP.value = row; detailVisible.value = true }

async function handleDelete(row) {
  await ElMessageBox.confirm('确定删除该IP及其所有资产吗？', '提示', { type: 'warning' })
  const res = await request.post('/asset/ip/delete', { ip: row.ip })
  if (res.code === 0) { ElMessage.success('删除成功'); loadData(); loadStat() }
}

async function handleBatchDelete() {
  if (selectedRows.value.length === 0) return
  await ElMessageBox.confirm(`确定删除选中的 ${selectedRows.value.length} 个IP及其所有资产吗？`, '提示', { type: 'warning' })
  const ips = selectedRows.value.map(row => row.ip)
  const res = await request.post('/asset/ip/batchDelete', { ips })
  if (res.code === 0) { ElMessage.success('删除成功'); selectedRows.value = []; loadData(); loadStat(); emit('data-changed') }
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
  
  if (command === 'selected-ip') {
    if (selectedRows.value.length === 0) {
      ElMessage.warning('请先选择要导出的IP')
      return
    }
    data = selectedRows.value
    filename = 'ips_selected.txt'
  } else {
    ElMessage.info('正在获取全部数据...')
    try {
      const res = await request.post('/asset/ip/list', {
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
    filename = 'ips_all.txt'
  }
  
  if (data.length === 0) {
    ElMessage.warning('没有可导出的数据')
    return
  }
  
  const seen = new Set()
  const exportData = []
  for (const row of data) {
    if (row.ip && !seen.has(row.ip)) {
      seen.add(row.ip)
      exportData.push(row.ip)
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

function getPortType(service) {
  if (!service) return 'info'
  if (['http', 'https'].includes(service)) return 'success'
  if (['ssh', 'ftp', 'telnet'].includes(service)) return 'warning'
  if (['mysql', 'redis', 'mongodb'].includes(service)) return 'danger'
  return 'info'
}

function refresh() { loadData(); loadStat() }

defineExpose({ refresh })
</script>

<style lang="scss" scoped>
.ip-view {
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
  .ip-cell { display: flex; align-items: center; gap: 8px;
    .ip-text { font-family: monospace; font-weight: 500; }
  }
  .port-list { display: flex; flex-wrap: wrap; gap: 4px;
    .port-tag { font-family: monospace; }
    .more-ports { color: var(--el-text-color-secondary); font-size: 12px; line-height: 22px; }
  }
  .domain-list {
    .domain-item { font-family: monospace; font-size: 12px; line-height: 1.6; color: var(--el-text-color-regular);
      &:hover { color: var(--el-color-primary); }
    }
    .more-domains { font-size: 12px; color: var(--el-text-color-secondary); cursor: pointer;
      &:hover { color: var(--el-color-primary); }
    }
  }
  .detail-ports { max-height: 150px; overflow-y: auto; }
  .pagination { margin-top: 16px; justify-content: flex-end; }
}
</style>
