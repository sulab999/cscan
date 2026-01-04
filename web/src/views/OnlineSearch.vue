<template>
  <div class="online-search-page">
    <!-- 搜索区域 -->
    <el-card class="search-card">
      <el-form :model="store.searchForm" inline>
        <el-form-item label="数据源">
          <el-select v-model="store.searchForm.source" style="width: 120px" @change="handleSourceChange">
            <el-option label="Fofa" value="fofa" />
            <el-option label="Hunter" value="hunter" />
            <el-option label="Quake" value="quake" />
          </el-select>
        </el-form-item>
        <el-form-item label="查询语句" style="flex: 1">
          <el-input
            v-model="store.searchForm.query"
            placeholder="输入查询语句，如: ip=1.1.1.1 或 domain=example.com"
            style="width: 400px"
            @keyup.enter="handleSearch"
          />
        </el-form-item>
        <el-form-item label="数量">
          <el-select v-model="store.searchForm.size" style="width: 100px">
            <el-option :value="10" label="10" />
            <el-option :value="50" label="50" />
            <el-option :value="100" label="100" />
            <el-option v-if="store.searchForm.source === 'fofa'" :value="500" label="500" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" @click="handleSearch">搜索</el-button>
          <el-button @click="handleImport" :disabled="!tableData.length">导入当前页</el-button>
          <el-button type="success" @click="handleImportAll" :disabled="!total" :loading="importAllLoading">导入全部</el-button>
          <el-button @click="showHelpDialog">语法帮助</el-button>
        </el-form-item>
      </el-form>

      <!-- 快捷查询 -->
      <div class="quick-search">
        <span class="label">快捷查询：</span>
        <el-tag
          v-for="item in quickQueries"
          :key="item.query"
          class="quick-tag"
          @click="applyQuickQuery(item)"
        >
          {{ item.label }}
        </el-tag>
      </div>
    </el-card>

    <!-- 结果表格 -->
    <el-card class="result-card">
      <template #header>
        <div class="card-header">
          <span>搜索结果</span>
          <span v-if="total > 0" class="total">共 {{ total }} 条</span>
        </div>
      </template>

      <el-table :data="tableData" v-loading="loading" stripe max-height="600">
        <el-table-column type="selection" width="50" />
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="port" label="端口" width="80" />
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="domain" label="域名" min-width="150" show-overflow-tooltip />
        <el-table-column prop="title" label="标题" min-width="200" show-overflow-tooltip />
        <el-table-column prop="server" label="Server" width="120" show-overflow-tooltip />
        <el-table-column prop="product" label="产品" width="120" show-overflow-tooltip />
        <el-table-column prop="country" label="国家" width="80" />
        <el-table-column prop="city" label="城市" width="100" />
        <el-table-column prop="icp" label="ICP备案" width="150" show-overflow-tooltip />
      </el-table>

      <el-pagination
        v-if="total > 0"
        v-model:current-page="store.searchForm.page"
        :page-size="store.searchForm.size"
        :total="total"
        layout="total, prev, pager, next"
        class="pagination"
        @current-change="handleSearch"
      />
    </el-card>

    <!-- 语法帮助对话框 -->
    <el-dialog v-model="helpDialogVisible" title="语法帮助" width="650px">
      <el-tabs v-model="helpTab">
        <el-tab-pane label="Fofa" name="fofa">
          <div class="syntax-help">
            <p><code>ip="1.1.1.1"</code> - 搜索指定IP</p>
            <p><code>domain="example.com"</code> - 搜索指定域名</p>
            <p><code>title="后台"</code> - 搜索标题包含关键词</p>
            <p><code>body="content"</code> - 搜索正文包含关键词</p>
            <p><code>port="80"</code> - 搜索指定端口</p>
            <p><code>icp="京ICP备"</code> - 搜索ICP备案</p>
            <p><code>org="公司名"</code> - 搜索组织</p>
            <p>组合查询: <code>ip="1.1.1.1" && port="80"</code></p>
          </div>
        </el-tab-pane>
        <el-tab-pane label="Hunter" name="hunter">
          <div class="syntax-help">
            <p><code>ip="1.1.1.1"</code> - 搜索指定IP</p>
            <p><code>domain.suffix="example.com"</code> - 搜索域名后缀</p>
            <p><code>web.title="后台"</code> - 搜索网页标题</p>
            <p><code>icp.name="公司名"</code> - 搜索ICP主体</p>
            <p><code>icp.number="京ICP备"</code> - 搜索ICP备案号</p>
            <p><code>port="443"</code> - 搜索指定端口</p>
          </div>
        </el-tab-pane>
        <el-tab-pane label="Quake" name="quake">
          <div class="syntax-help">
            <p><code>ip:"1.1.1.1"</code> - 搜索指定IP</p>
            <p><code>domain:"example.com"</code> - 搜索指定域名</p>
            <p><code>title:"后台"</code> - 搜索标题</p>
            <p><code>service:"http"</code> - 搜索服务类型</p>
            <p><code>port:"80"</code> - 搜索指定端口</p>
            <p><code>country:"CN"</code> - 搜索国家</p>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import request from '@/api/request'
import { useOnlineSearchStore } from '@/stores/onlineSearch'

const store = useOnlineSearchStore()

const loading = ref(false)
const importAllLoading = ref(false)
const helpDialogVisible = ref(false)
const helpTab = ref('fofa')

// 使用 store 中的数据
const tableData = computed(() => store.tableData)
const total = computed(() => store.total)

const quickQueries = [
  { label: 'IP搜索', query: 'ip="1.1.1.1"' },
  { label: '域名搜索', query: 'domain="example.com"' },
  { label: '标题搜索', query: 'title="后台管理"' },
  { label: 'ICP搜索', query: 'icp="京ICP备"' },
  { label: '端口搜索', query: 'port="3389"' },
]

async function handleSearch() {
  if (!store.searchForm.query) {
    ElMessage.warning('请输入查询语句')
    return
  }

  loading.value = true
  try {
    const res = await request.post('/onlineapi/search', {
      platform: store.searchForm.source,
      query: store.searchForm.query,
      page: store.searchForm.page,
      pageSize: store.searchForm.size
    })
    if (res.code === 0) {
      store.saveState(store.searchForm, res.list || [], res.total || 0)
    } else {
      ElMessage.error(res.msg || '搜索失败')
    }
  } finally {
    loading.value = false
  }
}

function applyQuickQuery(item) {
  store.searchForm.query = item.query
}

// 数据源切换时，如果当前数量超过限制则自动调整
function handleSourceChange() {
  if (store.searchForm.source !== 'fofa' && store.searchForm.size > 100) {
    store.searchForm.size = 100
  }
}

async function handleImport() {
  await ElMessageBox.confirm(`确定将当前页 ${tableData.value.length} 条数据导入到资产库吗？`, '提示')
  
  const res = await request.post('/onlineapi/import', { assets: tableData.value })
  
  if (res.code === 0) {
    ElMessage.success(res.msg || '导入成功')
  } else {
    ElMessage.error(res.msg || '导入失败')
  }
}

async function handleImportAll() {
  if (!store.searchForm.query) {
    ElMessage.warning('请先输入查询语句并搜索')
    return
  }

  // 计算预计导入数量
  const estimatedCount = total.value
  
  await ElMessageBox.confirm(
    `确定导入全部资产吗？将自动遍历所有页面，预计导入约 ${estimatedCount} 条数据`,
    '导入全部资产',
    { type: 'warning' }
  )

  importAllLoading.value = true
  try {
    // Hunter 和 Quake 单次最大 100，Fofa 可以 500
    const pageSize = store.searchForm.source === 'fofa' ? store.searchForm.size : Math.min(store.searchForm.size, 100)
    
    const res = await request.post('/onlineapi/importAll', {
      platform: store.searchForm.source,
      query: store.searchForm.query,
      pageSize: pageSize,
      maxPages: 0  // 0 表示不限制页数
    })

    if (res.code === 0) {
      ElMessage.success(res.msg || `成功导入${res.totalImport}条资产`)
    } else {
      ElMessage.error(res.msg || '导入失败')
    }
  } finally {
    importAllLoading.value = false
  }
}

function showHelpDialog() {
  helpDialogVisible.value = true
}
</script>

<style lang="scss" scoped>
.online-search-page {
  .search-card {
    margin-bottom: 20px;

    .quick-search {
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px solid #eee;

      .label {
        color: #666;
        margin-right: 10px;
      }

      .quick-tag {
        cursor: pointer;
        margin-right: 8px;

        &:hover {
          background: #409EFF;
          color: #fff;
        }
      }
    }
  }

  .result-card {
    margin-bottom: 20px;

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;

      .total {
        color: #999;
        font-size: 14px;
      }
    }

    .pagination {
      margin-top: 20px;
      justify-content: flex-end;
    }
  }

  .syntax-help {
    p {
      margin: 8px 0;
      line-height: 1.6;

      code {
        background: var(--el-fill-color-light);
        padding: 2px 6px;
        border-radius: 4px;
        color: #e83e8c;
      }
    }
  }
}
</style>
