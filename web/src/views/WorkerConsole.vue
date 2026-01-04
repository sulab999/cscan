<template>
  <div class="worker-console">
    <el-page-header @back="goBack" :title="'返回Worker列表'">
      <template #content>
        <span class="worker-title">{{ workerName }} - 探针控制台</span>
        <el-tag :type="workerStatus === 'running' ? 'success' : 'danger'" style="margin-left: 10px">
          {{ workerStatus === 'running' ? '在线' : '离线' }}
        </el-tag>
      </template>
    </el-page-header>

    <el-tabs v-model="activeTab" type="border-card" style="margin-top: 20px">
      <!-- 系统信息 -->
      <el-tab-pane label="系统信息" name="info">
        <div v-loading="infoLoading">
          <el-descriptions :column="2" border v-if="workerInfo">
            <el-descriptions-item label="Worker名称">{{ workerInfo.name }}</el-descriptions-item>
            <el-descriptions-item label="IP地址">{{ workerInfo.ip }}</el-descriptions-item>
            <el-descriptions-item label="操作系统">{{ workerInfo.os }}</el-descriptions-item>
            <el-descriptions-item label="架构">{{ workerInfo.arch }}</el-descriptions-item>
            <el-descriptions-item label="版本">{{ workerInfo.version || '-' }}</el-descriptions-item>
            <el-descriptions-item label="运行时长">{{ formatUptime(workerInfo.uptime) }}</el-descriptions-item>
            <el-descriptions-item label="CPU使用率">
              <el-progress :percentage="Math.round(workerInfo.cpuLoad || 0)" :color="getLoadColor(workerInfo.cpuLoad)" />
            </el-descriptions-item>
            <el-descriptions-item label="内存使用">
              <el-progress :percentage="getMemPercent(workerInfo)" :color="getLoadColor(getMemPercent(workerInfo))" />
              <span style="margin-left: 8px; font-size: 12px; color: #909399">
                {{ formatBytes(workerInfo.memUsed) }} / {{ formatBytes(workerInfo.memTotal) }}
              </span>
            </el-descriptions-item>
            <el-descriptions-item label="磁盘使用">
              <el-progress :percentage="getDiskPercent(workerInfo)" :color="getLoadColor(getDiskPercent(workerInfo))" />
              <span style="margin-left: 8px; font-size: 12px; color: #909399">
                {{ formatBytes(workerInfo.diskUsed) }} / {{ formatBytes(workerInfo.diskTotal) }}
              </span>
            </el-descriptions-item>
            <el-descriptions-item label="任务统计">
              已执行: {{ workerInfo.taskStarted || 0 }} | 运行中: {{ workerInfo.taskRunning || 0 }}
            </el-descriptions-item>
          </el-descriptions>

          <el-empty v-if="!workerInfo" description="无法获取Worker信息，请确保Worker在线" />
        </div>
      </el-tab-pane>

      <!-- 文件管理 -->
      <el-tab-pane label="文件管理" name="files">
        <div class="file-manager">
          <div class="file-toolbar">
            <el-breadcrumb separator="/">
              <el-breadcrumb-item 
                v-for="(part, index) in pathParts" 
                :key="index"
                @click="navigateToPath(index)"
                class="path-item"
              >
                {{ part || '根目录' }}
              </el-breadcrumb-item>
            </el-breadcrumb>
            <div class="file-actions">
              <el-button size="small" @click="refreshFiles" :loading="filesLoading">
                <el-icon><Refresh /></el-icon>刷新
              </el-button>
              <el-button size="small" type="primary" @click="showCreateDirDialog">
                <el-icon><FolderAdd /></el-icon>新建文件夹
              </el-button>
              <el-upload
                :show-file-list="false"
                :before-upload="handleUpload"
                :disabled="filesLoading"
              >
                <el-button size="small" type="success">
                  <el-icon><Upload /></el-icon>上传文件
                </el-button>
              </el-upload>
            </div>
          </div>

          <el-table :data="fileList" v-loading="filesLoading" @row-dblclick="handleFileClick" stripe>
            <el-table-column prop="name" label="名称" min-width="200">
              <template #default="{ row }">
                <span class="file-name" :class="{ 'is-dir': row.isDir }">
                  <el-icon v-if="row.isDir"><Folder /></el-icon>
                  <el-icon v-else><Document /></el-icon>
                  {{ row.name }}
                </span>
              </template>
            </el-table-column>
            <el-table-column prop="size" label="大小" width="120">
              <template #default="{ row }">
                {{ row.isDir ? '-' : formatBytes(row.size) }}
              </template>
            </el-table-column>
            <el-table-column prop="mode" label="权限" width="120" />
            <el-table-column prop="modTime" label="修改时间" width="180">
              <template #default="{ row }">
                {{ formatTime(row.modTime) }}
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button v-if="!row.isDir" size="small" type="primary" link @click="downloadFileHandler(row)">
                  下载
                </el-button>
                <el-popconfirm
                  :title="`确定要删除 ${row.name} 吗？`"
                  @confirm="deleteFileHandler(row)"
                >
                  <template #reference>
                    <el-button size="small" type="danger" link>删除</el-button>
                  </template>
                </el-popconfirm>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 终端 -->
      <el-tab-pane label="终端" name="terminal">
        <div class="terminal-container">
          <div class="terminal-toolbar">
            <el-button size="small" type="primary" @click="connectTerminal" :disabled="terminalConnected">
              {{ terminalConnected ? '已连接' : '连接终端' }}
            </el-button>
            <el-button size="small" @click="disconnectTerminal" :disabled="!terminalConnected">
              断开连接
            </el-button>
            <el-button size="small" @click="clearTerminal">清屏</el-button>
            <span v-if="terminalConnected" style="margin-left: 10px; color: #67c23a; font-size: 12px">
              <el-icon><CircleCheck /></el-icon> 终端已连接
            </span>
          </div>
          <div ref="terminalRef" class="terminal-output"></div>
          <div class="terminal-input" v-if="terminalConnected">
            <span class="prompt">$</span>
            <el-input
              v-model="terminalInput"
              placeholder="输入命令..."
              @keyup.enter="sendCommand"
              :disabled="!terminalConnected"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 审计日志 -->
      <el-tab-pane label="审计日志" name="audit">
        <el-table :data="auditLogs" v-loading="auditLoading" stripe>
          <el-table-column prop="createTime" label="时间" width="180">
            <template #default="{ row }">
              {{ formatAuditTime(row.createTime) }}
            </template>
          </el-table-column>
          <el-table-column prop="username" label="操作者" width="120">
            <template #default="{ row }">
              {{ row.username || row.clientIp || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="type" label="操作类型" width="140">
            <template #default="{ row }">
              <el-tag :type="getActionType(row.type)" size="small">{{ getActionLabel(row.type) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="目标" min-width="200">
            <template #default="{ row }">
              {{ row.path || row.command || row.sessionId || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="success" label="结果" width="100">
            <template #default="{ row }">
              <el-tag :type="row.success ? 'success' : 'danger'" size="small">
                {{ row.success ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="详情" min-width="200" show-overflow-tooltip>
            <template #default="{ row }">
              {{ row.error || (row.duration ? `耗时 ${row.duration}ms` : '-') }}
            </template>
          </el-table-column>
        </el-table>
        <el-pagination
          v-model:current-page="auditPage"
          :page-size="20"
          :total="auditTotal"
          layout="total, prev, pager, next"
          @current-change="loadAuditLogs"
          style="margin-top: 15px; justify-content: flex-end"
        />
      </el-tab-pane>
    </el-tabs>

    <!-- 新建文件夹对话框 -->
    <el-dialog v-model="createDirDialogVisible" title="新建文件夹" width="400px">
      <el-input v-model="newDirName" placeholder="请输入文件夹名称" />
      <template #footer>
        <el-button @click="createDirDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="createDirHandler" :loading="createDirLoading">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { 
  Refresh, FolderAdd, Upload, Folder, Document, CircleCheck 
} from '@element-plus/icons-vue'
import { 
  getWorkerInfo, listFiles, uploadFile, downloadFile, deleteFile, createDir,
  openTerminal, closeTerminal, execCommand, getAuditLogs 
} from '@/api/worker'
import { useUserStore } from '@/stores/user'

const route = useRoute()
const router = useRouter()
const userStore = useUserStore()

const workerName = ref('')
const workerStatus = ref('offline')
const activeTab = ref('info')

// 系统信息
const workerInfo = ref(null)
const infoLoading = ref(false)

// 文件管理
const currentPath = ref('.')
const fileList = ref([])
const filesLoading = ref(false)
const createDirDialogVisible = ref(false)
const newDirName = ref('')
const createDirLoading = ref(false)

// 终端
const terminalRef = ref(null)
const terminalConnected = ref(false)
const terminalInput = ref('')
const terminalOutput = ref([])
const terminalSessionId = ref('')
let terminalWs = null

// 审计日志
const auditLogs = ref([])
const auditLoading = ref(false)
const auditPage = ref(1)
const auditTotal = ref(0)

const pathParts = computed(() => {
  if (!currentPath.value || currentPath.value === '.') return ['']
  return ['', ...currentPath.value.split('/').filter(p => p && p !== '.')]
})

onMounted(() => {
  workerName.value = route.params.name || route.query.name
  if (!workerName.value) {
    ElMessage.error('未指定Worker名称')
    router.push('/worker')
    return
  }
  loadWorkerInfo()
})

onUnmounted(() => {
  disconnectTerminal()
})

watch(activeTab, (tab) => {
  if (tab === 'files' && fileList.value.length === 0) {
    loadFiles()
  } else if (tab === 'audit' && auditLogs.value.length === 0) {
    loadAuditLogs()
  }
})

function goBack() {
  router.push('/worker')
}

async function loadWorkerInfo() {
  infoLoading.value = true
  try {
    const res = await getWorkerInfo(workerName.value)
    if (res.code === 0) {
      workerInfo.value = res.data
      workerStatus.value = 'running'
    } else {
      workerStatus.value = 'offline'
      ElMessage.warning(res.message || '获取Worker信息失败')
    }
  } catch (e) {
    workerStatus.value = 'offline'
    ElMessage.error('获取Worker信息失败: ' + e.message)
  } finally {
    infoLoading.value = false
  }
}

async function loadFiles() {
  filesLoading.value = true
  try {
    const res = await listFiles(workerName.value, currentPath.value)
    if (res.code === 0 && res.data) {
      fileList.value = res.data.files || []
    } else {
      ElMessage.error(res.message || '获取文件列表失败')
    }
  } catch (e) {
    ElMessage.error('获取文件列表失败: ' + e.message)
  } finally {
    filesLoading.value = false
  }
}

function refreshFiles() {
  loadFiles()
}

function handleFileClick(row) {
  if (row.isDir) {
    currentPath.value = currentPath.value === '.' 
      ? row.name 
      : `${currentPath.value}/${row.name}`
    loadFiles()
  }
}

function navigateToPath(index) {
  if (index === 0) {
    currentPath.value = '.'
  } else {
    currentPath.value = pathParts.value.slice(1, index + 1).join('/')
  }
  loadFiles()
}

function showCreateDirDialog() {
  newDirName.value = ''
  createDirDialogVisible.value = true
}

async function createDirHandler() {
  if (!newDirName.value.trim()) {
    ElMessage.warning('请输入文件夹名称')
    return
  }
  createDirLoading.value = true
  try {
    const path = currentPath.value === '.' 
      ? newDirName.value 
      : `${currentPath.value}/${newDirName.value}`
    const res = await createDir(workerName.value, path)
    if (res.code === 0) {
      ElMessage.success('创建成功')
      createDirDialogVisible.value = false
      loadFiles()
    } else {
      ElMessage.error(res.message || '创建失败')
    }
  } catch (e) {
    ElMessage.error('创建失败: ' + e.message)
  } finally {
    createDirLoading.value = false
  }
}

async function handleUpload(file) {
  try {
    const res = await uploadFile(workerName.value, currentPath.value, file)
    if (res.code === 0) {
      ElMessage.success('上传成功')
      loadFiles()
    } else {
      ElMessage.error(res.message || '上传失败')
    }
  } catch (e) {
    ElMessage.error('上传失败: ' + e.message)
  }
  return false
}

async function downloadFileHandler(row) {
  try {
    const path = currentPath.value === '.' ? row.name : `${currentPath.value}/${row.name}`
    const res = await downloadFile(workerName.value, path)
    if (res.code === 0 && res.data) {
      // 将 Base64 转为 Blob 并下载
      const byteCharacters = atob(res.data.data)
      const byteNumbers = new Array(byteCharacters.length)
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i)
      }
      const byteArray = new Uint8Array(byteNumbers)
      const blob = new Blob([byteArray])
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = row.name
      link.click()
      window.URL.revokeObjectURL(url)
    } else {
      ElMessage.error(res.message || '下载失败')
    }
  } catch (e) {
    ElMessage.error('下载失败: ' + e.message)
  }
}

async function deleteFileHandler(row) {
  try {
    const path = currentPath.value === '.' ? row.name : `${currentPath.value}/${row.name}`
    const res = await deleteFile(workerName.value, path)
    if (res.code === 0) {
      ElMessage.success('删除成功')
      loadFiles()
    } else {
      ElMessage.error(res.message || '删除失败')
    }
  } catch (e) {
    ElMessage.error('删除失败: ' + e.message)
  }
}

// 终端功能
async function connectTerminal() {
  // 直接连接 WebSocket，WebSocket handler 会自动打开终端会话
  connectTerminalWS()
}

function connectTerminalWS() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  // 生成一个 sessionId
  terminalSessionId.value = Date.now().toString()
  
  // 获取 token 用于 WebSocket 认证
  const token = userStore.token || ''
  
  const wsUrl = `${protocol}//${window.location.host}/api/v1/worker/console/terminal?name=${workerName.value}&sessionId=${terminalSessionId.value}&token=${encodeURIComponent(token)}`
  
  console.log('[Terminal] Connecting to:', wsUrl)
  terminalWs = new WebSocket(wsUrl)
  
  terminalWs.onopen = () => {
    console.log('[Terminal] WebSocket connected')
    terminalConnected.value = true
    appendTerminalOutput('终端已连接\n', 'info')
  }
  
  terminalWs.onmessage = (event) => {
    console.log('[Terminal] Received:', event.data)
    try {
      const data = JSON.parse(event.data)
      if (data.type === 'output') {
        appendTerminalOutput(data.data)
      } else if (data.type === 'error') {
        appendTerminalOutput(data.error || data.data, 'error')
      } else if (data.type === 'pong') {
        // 心跳响应，忽略
      }
    } catch (e) {
      // 非 JSON 数据，直接显示
      appendTerminalOutput(event.data)
    }
  }
  
  terminalWs.onclose = (event) => {
    console.log('[Terminal] WebSocket closed:', event.code, event.reason)
    terminalConnected.value = false
    appendTerminalOutput('\n终端已断开\n', 'info')
  }
  
  terminalWs.onerror = (error) => {
    console.error('[Terminal] WebSocket error:', error)
    ElMessage.error('终端连接错误')
  }
}

function disconnectTerminal() {
  if (terminalWs) {
    terminalWs.close()
    terminalWs = null
  }
  if (terminalSessionId.value) {
    closeTerminal(workerName.value, terminalSessionId.value).catch(() => {})
    terminalSessionId.value = ''
  }
  terminalConnected.value = false
}

function sendCommand() {
  if (!terminalInput.value.trim() || !terminalWs) return
  
  const cmd = terminalInput.value
  appendTerminalOutput(`$ ${cmd}\n`, 'command')
  
  // 发送命令到 WebSocket
  terminalWs.send(JSON.stringify({
    type: 'input',
    command: cmd  // 使用 command 字段，后端会记录命令历史
  }))
  
  terminalInput.value = ''
}

function appendTerminalOutput(text, type = 'output') {
  if (!terminalRef.value) return
  
  const span = document.createElement('span')
  span.textContent = text
  span.className = `terminal-${type}`
  terminalRef.value.appendChild(span)
  terminalRef.value.scrollTop = terminalRef.value.scrollHeight
}

function clearTerminal() {
  if (terminalRef.value) {
    terminalRef.value.innerHTML = ''
  }
}

// 审计日志
async function loadAuditLogs() {
  auditLoading.value = true
  try {
    const res = await getAuditLogs(workerName.value, auditPage.value, 20)
    if (res.code === 0) {
      auditLogs.value = res.list || res.data?.list || []
      auditTotal.value = res.total || res.data?.total || 0
    } else {
      ElMessage.error(res.message || '获取审计日志失败')
    }
  } catch (e) {
    ElMessage.error('获取审计日志失败: ' + e.message)
  } finally {
    auditLoading.value = false
  }
}

// 工具函数
function formatUptime(seconds) {
  if (!seconds) return '-'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}天${hours}小时`
  if (hours > 0) return `${hours}小时${mins}分钟`
  return `${mins}分钟`
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function formatTime(timestamp) {
  if (!timestamp) return '-'
  const date = new Date(timestamp * 1000)
  return date.toLocaleString('zh-CN')
}

function formatAuditTime(timeStr) {
  if (!timeStr) return '-'
  const date = new Date(timeStr)
  return date.toLocaleString('zh-CN')
}

function getLoadColor(value) {
  if (value < 50) return '#67C23A'
  if (value < 80) return '#E6A23C'
  return '#F56C6C'
}

function getMemPercent(info) {
  if (!info?.memTotal) return 0
  return Math.round((info.memUsed / info.memTotal) * 100)
}

function getDiskPercent(info) {
  if (!info?.diskTotal) return 0
  return Math.round((info.diskUsed / info.diskTotal) * 100)
}

function getActionType(action) {
  const types = {
    'file_upload': 'primary',
    'file_download': 'success',
    'file_delete': 'danger',
    'file_list': 'info',
    'file_mkdir': 'primary',
    'terminal_exec': 'warning',
    'terminal_open': 'success',
    'terminal_close': 'info',
    'console_info': 'info'
  }
  return types[action] || 'info'
}

function getActionLabel(action) {
  const labels = {
    'file_upload': '上传文件',
    'file_download': '下载文件',
    'file_delete': '删除文件',
    'file_list': '浏览目录',
    'file_mkdir': '创建目录',
    'terminal_exec': '执行命令',
    'terminal_open': '打开终端',
    'terminal_close': '关闭终端',
    'console_info': '查看信息'
  }
  return labels[action] || action
}
</script>


<style lang="scss" scoped>
.worker-console {
  .worker-title {
    font-size: 16px;
    font-weight: 600;
  }

  .file-manager {
    .file-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
      padding: 10px;
      background: #f5f7fa;
      border-radius: 4px;

      .path-item {
        cursor: pointer;
        &:hover {
          color: #409eff;
        }
      }

      .file-actions {
        display: flex;
        gap: 10px;
      }
    }

    .file-name {
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;

      &.is-dir {
        color: #409eff;
        font-weight: 500;
      }

      &:hover {
        color: #409eff;
      }
    }
  }

  .terminal-container {
    .terminal-toolbar {
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .terminal-output {
      height: 400px;
      background: #1e1e1e;
      border-radius: 4px;
      padding: 10px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 13px;
      color: #d4d4d4;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;

      :deep(.terminal-output) {
        color: #d4d4d4;
      }

      :deep(.terminal-command) {
        color: #569cd6;
      }

      :deep(.terminal-error) {
        color: #f14c4c;
      }

      :deep(.terminal-info) {
        color: #6a9955;
      }
    }

    .terminal-input {
      display: flex;
      align-items: center;
      margin-top: 10px;
      background: #1e1e1e;
      border-radius: 4px;
      padding: 5px 10px;

      .prompt {
        color: #569cd6;
        font-family: 'Consolas', 'Monaco', monospace;
        margin-right: 8px;
      }

      :deep(.el-input__wrapper) {
        background: transparent;
        box-shadow: none;
      }

      :deep(.el-input__inner) {
        color: #d4d4d4;
        font-family: 'Consolas', 'Monaco', monospace;
      }
    }
  }
}
</style>
