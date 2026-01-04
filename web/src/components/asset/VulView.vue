<template>
  <div class="vul-view">
    <!-- 搜索区域 -->
    <el-card class="search-card">
      <el-form :model="searchForm" inline>
        <el-form-item label="目标">
          <el-input v-model="searchForm.authority" placeholder="IP:端口" clearable @keyup.enter="handleSearch" />
        </el-form-item>
        <el-form-item label="危害等级">
          <el-select v-model="searchForm.severity" placeholder="全部" clearable style="width: 120px">
            <el-option label="严重" value="critical" />
            <el-option label="高危" value="high" />
            <el-option label="中危" value="medium" />
            <el-option label="低危" value="low" />
            <el-option label="信息" value="info" />
            <el-option label="未知" value="unknown" />
          </el-select>
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="searchForm.source" placeholder="全部" clearable style="width: 120px">
            <el-option label="Nuclei" value="nuclei" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">搜索</el-button>
          <el-button @click="handleReset">重置</el-button>
          <el-button type="danger" plain @click="handleClear">
            清空数据
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 统计信息 -->
    <el-row :gutter="16" class="stat-row">
      <el-col :span="4">
        <el-card class="stat-card">
          <div class="stat-value">{{ stat.total }}</div>
          <div class="stat-label">漏洞总数</div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card class="stat-card critical">
          <div class="stat-value">{{ stat.critical }}</div>
          <div class="stat-label">严重</div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card class="stat-card high">
          <div class="stat-value">{{ stat.high }}</div>
          <div class="stat-label">高危</div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card class="stat-card medium">
          <div class="stat-value">{{ stat.medium }}</div>
          <div class="stat-label">中危</div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card class="stat-card low">
          <div class="stat-value">{{ stat.low }}</div>
          <div class="stat-label">低危</div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card class="stat-card info">
          <div class="stat-value">{{ stat.info }}</div>
          <div class="stat-label">信息</div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 数据表格 -->
    <el-card class="table-card">
      <div class="table-header">
        <span class="total-info">共 {{ pagination.total }} 条漏洞</span>
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
                <el-dropdown-item command="selected-target" :disabled="selectedRows.length === 0">导出选中目标 ({{ selectedRows.length }})</el-dropdown-item>
                <el-dropdown-item command="selected-url" :disabled="selectedRows.length === 0">导出选中URL ({{ selectedRows.length }})</el-dropdown-item>
                <el-dropdown-item divided command="all-target">导出全部目标</el-dropdown-item>
                <el-dropdown-item command="all-url">导出全部URL</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
      <el-table :data="tableData" v-loading="loading" stripe max-height="500" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="50" />
        <el-table-column prop="authority" label="目标" min-width="150" />
        <el-table-column prop="url" label="URL" min-width="250" show-overflow-tooltip />
        <el-table-column prop="pocFile" label="POC" min-width="200" show-overflow-tooltip />
        <el-table-column prop="severity" label="危害等级" width="100">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)" size="small">{{ getSeverityLabel(row.severity) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="来源" width="100" />
        <el-table-column prop="createTime" label="发现时间" width="160" />
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
    <el-dialog v-model="detailVisible" title="漏洞详情" width="800px">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="目标">{{ currentVul.authority }}</el-descriptions-item>
        <el-descriptions-item label="危害等级">
          <el-tag :type="getSeverityType(currentVul.severity)">{{ getSeverityLabel(currentVul.severity) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="URL" :span="2">{{ currentVul.url }}</el-descriptions-item>
        <el-descriptions-item label="POC文件" :span="2">{{ currentVul.pocFile }}</el-descriptions-item>
        <el-descriptions-item label="来源">{{ currentVul.source }}</el-descriptions-item>
        <el-descriptions-item label="发现时间">{{ currentVul.createTime }}</el-descriptions-item>
        <el-descriptions-item label="验证结果" :span="2">
          <pre class="result-pre">{{ currentVul.result }}</pre>
        </el-descriptions-item>
      </el-descriptions>
      <template v-if="currentVul.evidence">
        <el-divider content-position="left">证据链</el-divider>
        <el-descriptions :column="1" border>
          <el-descriptions-item label="cURL命令" v-if="currentVul.evidence.curlCommand">
            <pre class="result-pre">{{ currentVul.evidence.curlCommand }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="请求内容" v-if="currentVul.evidence.request">
            <pre class="result-pre">{{ currentVul.evidence.request }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="响应内容" v-if="currentVul.evidence.response">
            <pre class="result-pre">{{ currentVul.evidence.response }}</pre>
          </el-descriptions-item>
        </el-descriptions>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown } from '@element-plus/icons-vue'
import request from '@/api/request'

const emit = defineEmits(['data-changed'])

const loading = ref(false)
const tableData = ref([])
const detailVisible = ref(false)
const currentVul = ref({})
const selectedRows = ref([])

const searchForm = reactive({ authority: '', severity: '', source: '' })
const stat = reactive({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 })
const pagination = reactive({ page: 1, pageSize: 20, total: 0 })

function handleWorkspaceChanged() { pagination.page = 1; loadData(); loadStat() }

onMounted(() => {
  loadData(); loadStat()
  window.addEventListener('workspace-changed', handleWorkspaceChanged)
})
onUnmounted(() => { window.removeEventListener('workspace-changed', handleWorkspaceChanged) })

async function loadData() {
  loading.value = true
  try {
    const res = await request.post('/vul/list', {
      ...searchForm, page: pagination.page, pageSize: pagination.pageSize
    })
    if (res.code === 0) { tableData.value = res.list || []; pagination.total = res.total }
  } finally { loading.value = false }
}

async function loadStat() {
  try {
    const res = await request.post('/vul/stat', {})
    if (res.code === 0) {
      stat.total = res.total || 0
      stat.critical = res.critical || 0
      stat.high = res.high || 0
      stat.medium = res.medium || 0
      stat.low = res.low || 0
      stat.info = res.info || 0
    }
  } catch (e) { console.error(e) }
}

function handleSearch() { pagination.page = 1; loadData() }
function handleReset() {
  Object.assign(searchForm, { authority: '', severity: '', source: '' })
  handleSearch()
}

function handleSelectionChange(rows) { selectedRows.value = rows }

function getSeverityType(severity) {
  const map = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: '', unknown: 'info' }
  return map[severity] || ''
}

function getSeverityLabel(severity) {
  const map = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息', unknown: '未知' }
  return map[severity] || severity
}

async function showDetail(row) {
  try {
    const res = await request.post('/vul/detail', { id: row.id })
    currentVul.value = res.code === 0 && res.data ? res.data : row
  } catch (e) { currentVul.value = row }
  detailVisible.value = true
}

async function handleDelete(row) {
  await ElMessageBox.confirm('确定删除该漏洞记录吗？', '提示', { type: 'warning' })
  const res = await request.post('/vul/delete', { id: row.id })
  if (res.code === 0) { ElMessage.success('删除成功'); loadData(); loadStat() }
}

async function handleBatchDelete() {
  if (selectedRows.value.length === 0) return
  await ElMessageBox.confirm(`确定删除选中的 ${selectedRows.value.length} 条漏洞记录吗？`, '提示', { type: 'warning' })
  const ids = selectedRows.value.map(row => row.id)
  const res = await request.post('/vul/batchDelete', { ids })
  if (res.code === 0) { ElMessage.success('删除成功'); selectedRows.value = []; loadData(); loadStat(); emit('data-changed') }
}

async function handleClear() {
  await ElMessageBox.confirm('确定清空所有漏洞数据吗？此操作不可恢复！', '警告', { type: 'error', confirmButtonText: '确定清空', cancelButtonText: '取消' })
  const res = await request.post('/vul/clear', {})
  if (res.code === 0) { ElMessage.success(res.msg || '清空成功'); selectedRows.value = []; loadData(); loadStat(); emit('data-changed') }
  else { ElMessage.error(res.msg || '清空失败') }
}

// 导出功能
async function handleExport(command) {
  let data = []
  let filename = ''
  
  if (command === 'selected-target' || command === 'selected-url') {
    if (selectedRows.value.length === 0) {
      ElMessage.warning('请先选择要导出的漏洞')
      return
    }
    data = selectedRows.value
    filename = command === 'selected-target' ? 'vul_targets_selected.txt' : 'vul_urls_selected.txt'
  } else {
    ElMessage.info('正在获取全部数据...')
    try {
      const res = await request.post('/vul/list', {
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
    filename = command === 'all-target' ? 'vul_targets_all.txt' : 'vul_urls_all.txt'
  }
  
  if (data.length === 0) {
    ElMessage.warning('没有可导出的数据')
    return
  }
  
  // 提取数据并去重
  const seen = new Set()
  const exportData = []
  
  if (command.includes('target')) {
    for (const row of data) {
      if (row.authority && !seen.has(row.authority)) {
        seen.add(row.authority)
        exportData.push(row.authority)
      }
    }
  } else {
    for (const row of data) {
      if (row.url && !seen.has(row.url)) {
        seen.add(row.url)
        exportData.push(row.url)
      }
    }
  }
  
  if (exportData.length === 0) {
    ElMessage.warning('没有可导出的数据')
    return
  }
  
  // 下载文件
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
.vul-view {
  .search-card { margin-bottom: 16px; }
  .stat-row {
    margin-bottom: 16px;
    .stat-card {
      text-align: center;
      .stat-value { font-size: 24px; font-weight: 600; color: var(--el-color-primary); }
      .stat-label { color: var(--el-text-color-secondary); margin-top: 8px; font-size: 13px; }
      &.critical .stat-value { color: #f56c6c; }
      &.high .stat-value { color: #e6a23c; }
      &.medium .stat-value { color: #f0ad4e; }
      &.low .stat-value { color: #909399; }
      &.info .stat-value { color: #409eff; }
    }
  }
  .table-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    .total-info { color: var(--el-text-color-secondary); font-size: 14px; }
  }
  .pagination { margin-top: 20px; justify-content: flex-end; }
  .result-pre {
    margin: 0; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow: auto;
    background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 6px;
    font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; line-height: 1.5;
  }
}
</style>
