<template>
  <div class="asset-management-page">
    <!-- Tab页切换 -->
    <el-tabs v-model="activeTab" type="border-card" class="asset-tabs" @tab-change="handleTabChange">
      <!-- 全局查看 Tab -->
      <el-tab-pane label="全局查看" name="all">
        <AssetAllView ref="allViewRef" @data-changed="handleDataChanged" />
      </el-tab-pane>

      <!-- 站点管理 Tab -->
      <el-tab-pane label="站点管理" name="site">
        <SiteView ref="siteViewRef" @data-changed="handleDataChanged" />
      </el-tab-pane>

      <!-- 域名管理 Tab -->
      <el-tab-pane label="域名管理" name="domain">
        <DomainView ref="domainViewRef" @data-changed="handleDataChanged" />
      </el-tab-pane>

      <!-- IP管理 Tab -->
      <el-tab-pane label="IP管理" name="ip">
        <IPView ref="ipViewRef" @data-changed="handleDataChanged" />
      </el-tab-pane>

      <!-- 漏洞管理 Tab -->
      <el-tab-pane label="漏洞管理" name="vul">
        <VulView ref="vulViewRef" @data-changed="handleDataChanged" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch, defineAsyncComponent } from 'vue'
import { useRoute, useRouter } from 'vue-router'

// 异步加载各个视图组件
const AssetAllView = defineAsyncComponent(() => import('@/components/asset/AssetAllView.vue'))
const SiteView = defineAsyncComponent(() => import('@/components/asset/SiteView.vue'))
const DomainView = defineAsyncComponent(() => import('@/components/asset/DomainView.vue'))
const IPView = defineAsyncComponent(() => import('@/components/asset/IPView.vue'))
const VulView = defineAsyncComponent(() => import('@/components/asset/VulView.vue'))

const route = useRoute()
const router = useRouter()

// 有效的tab名称
const validTabs = ['all', 'site', 'domain', 'ip', 'vul']

// 从URL获取初始tab，默认为'all'
const getInitialTab = () => {
  const tab = route.query.tab
  return validTabs.includes(tab) ? tab : 'all'
}

const activeTab = ref(getInitialTab())
const allViewRef = ref(null)
const siteViewRef = ref(null)
const domainViewRef = ref(null)
const ipViewRef = ref(null)
const vulViewRef = ref(null)

// 监听路由变化，更新activeTab
watch(() => route.query.tab, (newTab) => {
  if (validTabs.includes(newTab) && newTab !== activeTab.value) {
    activeTab.value = newTab
  }
})

// 工作空间切换时刷新当前Tab数据
function handleWorkspaceChanged() {
  refreshCurrentTab()
}

function handleTabChange(tabName) {
  // Tab切换时更新URL
  router.replace({ query: { ...route.query, tab: tabName } })
}

// 数据变化时刷新所有Tab
function handleDataChanged() {
  // 刷新所有视图
  allViewRef.value?.refresh?.()
  siteViewRef.value?.refresh?.()
  domainViewRef.value?.refresh?.()
  ipViewRef.value?.refresh?.()
  vulViewRef.value?.refresh?.()
}

function refreshCurrentTab() {
  switch (activeTab.value) {
    case 'all':
      allViewRef.value?.refresh?.()
      break
    case 'site':
      siteViewRef.value?.refresh?.()
      break
    case 'domain':
      domainViewRef.value?.refresh?.()
      break
    case 'ip':
      ipViewRef.value?.refresh?.()
      break
    case 'vul':
      vulViewRef.value?.refresh?.()
      break
  }
}

onMounted(() => {
  window.addEventListener('workspace-changed', handleWorkspaceChanged)
  // 如果URL没有tab参数，添加默认的tab参数
  if (!route.query.tab) {
    router.replace({ query: { ...route.query, tab: activeTab.value } })
  }
})

onUnmounted(() => {
  window.removeEventListener('workspace-changed', handleWorkspaceChanged)
})
</script>

<style lang="scss" scoped>
.asset-management-page {
  height: 100%;
  
  .asset-tabs {
    height: 100%;
    
    :deep(.el-tabs__content) {
      padding: 16px;
      height: calc(100% - 50px);
      overflow-y: auto;
    }
    
    :deep(.el-tab-pane) {
      height: 100%;
    }
  }
}
</style>
