<template>
  <div class="domain-view">
    <!-- 搜索区域 -->
    <el-card class="search-card">
      <el-form :inline="true" class="search-form">
        <el-form-item label="域名">
          <el-input v-model="searchForm.domain" placeholder="域名" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="根域名">
          <el-input v-model="searchForm.rootDomain" placeholder="根域名" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="IP">
          <el-input v-model="searchForm.ip" placeholder="解析IP" clearable @keyup.enter="handleSearch" />
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
          <div class="stat-label">域名总数</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.rootDomainCount }}</div>
          <div class="stat-label">根域名数</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.resolvedCount }}</div>
          <div class="stat-label">已解析</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.newCount }}</div>
          <div class="stat-label">新增域名</div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 数据表格 -->
    <el-card class="table-card">
      <div class="table-header">
        <span class="total-info">共 {{ pagination.total }} 个域名</span>
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
                <el-dropdown-item command="selected-domain" :disabled="selectedRows.length === 0">导出选中域名 ({{ selectedRows.length }})</el-dropdown-item>
                <el-dropdown-item divided command="all-domain">导出全部域名</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
      
      <el-table :data="tableData" v-loading="loading" max-height="500" stripe @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="40" />
        <el-table-column label="域名" min-width="250">
          <template #default="{ row }">
            <div class="domain-cell">
              <span class="domain-name">{{ row.domain }}</span>
              <el-tag v-if="row.isNew" type="success" size="small" effect="dark" class="new-tag">新</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="根域名" width="160">
          <template #default="{ row }">{{ row.rootDomain || '-' }}</template>
        </el-table-column>
        <el-table-column label="解析IP" min-width="200">
          <template #default="{ row }">
            <div v-if="row.ips && row.ips.length > 0">
              <el-tag v-for="ip in row.ips.slice(0, 3)" :key="ip" size="small" type="info" style="margin-right: 4px">{{ ip }}</el-tag>
              <span v-if="row.ips.length > 3" class="more-ips">+{{ row.ips.length - 3 }}</span>
            </div>
            <span v-else class="no-resolve">未解析</span>
          </template>
        </el-table-column>
        <el-table-column label="CNAME" width="180">
          <template #default="{ row }">{{ row.cname || '-' }}</template>
        </el-table-column>
        <el-table-column label="来源" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.source || 'subfinder' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="组织" width="120">
          <template #default="{ row }">{{ row.orgName || '默认组织' }}</template>
        </el-table-column>
        <el-table-column label="发现时间" width="160">
          <template #default="{ row }">{{ row.createTime }}</template>
        </el-table-column>
        <el-table-column label="操作" width="80" fixed="right">
          <template #default="{ row }">
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

const searchForm = reactive({ domain: '', rootDomain: '', ip: '', orgId: '' })
const stat = reactive({ total: 0, rootDomainCount: 0, resolvedCount: 0, newCount: 0 })
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
    const res = await request.post('/asset/domain/list', {
      page: pagination.page, pageSize: pagination.pageSize,
      domain: searchForm.domain, rootDomain: searchForm.rootDomain,
      ip: searchForm.ip, orgId: searchForm.orgId
    })
    if (res.code === 0) { tableData.value = res.list || []; pagination.total = res.total || 0 }
  } finally { loading.value = false }
}

async function loadStat() {
  try {
    const res = await request.post('/asset/domain/stat', {})
    if (res.code === 0) {
      stat.total = res.total || 0
      stat.rootDomainCount = res.rootDomainCount || 0
      stat.resolvedCount = res.resolvedCount || 0
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
  Object.assign(searchForm, { domain: '', rootDomain: '', ip: '', orgId: '' })
  handleSearch()
}

function handleSelectionChange(rows) { selectedRows.value = rows }

async function handleDelete(row) {
  await ElMessageBox.confirm('确定删除该域名吗？', '提示', { type: 'warning' })
  const res = await request.post('/asset/domain/delete', { id: row.id })
  if (res.code === 0) { ElMessage.success('删除成功'); loadData(); loadStat() }
}

async function handleBatchDelete() {
  if (selectedRows.value.length === 0) return
  await ElMessageBox.confirm(`确定删除选中的 ${selectedRows.value.length} 个域名吗？`, '提示', { type: 'warning' })
  const ids = selectedRows.value.map(row => row.id)
  const res = await request.post('/asset/domain/batchDelete', { ids })
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
  
  if (command === 'selected-domain') {
    if (selectedRows.value.length === 0) {
      ElMessage.warning('请先选择要导出的域名')
      return
    }
    data = selectedRows.value
    filename = 'domains_selected.txt'
  } else {
    ElMessage.info('正在获取全部数据...')
    try {
      const res = await request.post('/asset/domain/list', {
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
    filename = 'domains_all.txt'
  }
  
  if (data.length === 0) {
    ElMessage.warning('没有可导出的数据')
    return
  }
  
  const seen = new Set()
  const exportData = []
  for (const row of data) {
    if (row.domain && !seen.has(row.domain)) {
      seen.add(row.domain)
      exportData.push(row.domain)
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

function refresh() { loadData(); loadStat() }

defineExpose({ refresh })
</script>

<style lang="scss" scoped>
.domain-view {
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
  .domain-cell { display: flex; align-items: center;
    .domain-name { font-family: monospace; }
    .new-tag { margin-left: 8px; }
  }
  .more-ips { color: var(--el-text-color-secondary); font-size: 12px; }
  .no-resolve { color: var(--el-text-color-placeholder); }
  .pagination { margin-top: 16px; justify-content: flex-end; }
}
</style>
