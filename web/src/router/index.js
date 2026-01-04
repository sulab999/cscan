import { createRouter, createWebHistory } from 'vue-router'
import { useUserStore } from '@/stores/user'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    component: () => import('@/layouts/MainLayout.vue'),
    redirect: '/dashboard',
    meta: { requiresAuth: true },
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: '工作台', icon: 'Odometer' }
      },
      {
        path: 'asset-management',
        name: 'AssetManagement',
        component: () => import('@/views/AssetManagement.vue'),
        meta: { title: '资产管理', icon: 'DataAnalysis' }
      },
      {
        path: 'site',
        name: 'Site',
        component: () => import('@/views/Site.vue'),
        meta: { title: '站点管理', icon: 'Monitor', hidden: true }
      },
      {
        path: 'domain',
        name: 'Domain',
        component: () => import('@/views/Domain.vue'),
        meta: { title: '域名管理', icon: 'Link', hidden: true }
      },
      {
        path: 'ip',
        name: 'IP',
        component: () => import('@/views/IP.vue'),
        meta: { title: 'IP管理', icon: 'Position', hidden: true }
      },
      {
        path: 'asset',
        name: 'Asset',
        component: () => import('@/views/Asset.vue'),
        meta: { title: '资产管理', icon: 'Monitor', hidden: true }
      },
      {
        path: 'task/create',
        name: 'TaskCreate',
        component: () => import('@/views/TaskCreate.vue'),
        meta: { title: '新建任务', icon: 'List', hidden: true }
      },
      {
        path: 'task/edit/:id',
        name: 'TaskEdit',
        component: () => import('@/views/TaskCreate.vue'),
        meta: { title: '编辑任务', icon: 'List', hidden: true }
      },
      {
        path: 'task',
        name: 'Task',
        component: () => import('@/views/Task.vue'),
        meta: { title: '任务管理', icon: 'List' }
      },
      {
        path: 'vul',
        name: 'Vul',
        component: () => import('@/views/Vul.vue'),
        meta: { title: '漏洞管理', icon: 'Warning', hidden: true }
      },
      {
        path: 'online-search',
        name: 'OnlineSearch',
        component: () => import('@/views/OnlineSearch.vue'),
        meta: { title: '在线搜索', icon: 'Search' }
      },
      {
        path: 'workspace',
        name: 'Workspace',
        redirect: '/settings?tab=workspace',
        meta: { title: '工作空间', icon: 'Folder', hidden: true }
      },
      {
        path: 'worker',
        name: 'Worker',
        component: () => import('@/views/Worker.vue'),
        meta: { title: 'Worker管理', icon: 'Connection' }
      },
      {
        path: 'worker/console/:name',
        name: 'WorkerConsole',
        component: () => import('@/views/WorkerConsole.vue'),
        meta: { title: 'Worker控制台', icon: 'Monitor', hidden: true }
      },
      {
        path: 'poc',
        name: 'Poc',
        component: () => import('@/views/Poc.vue'),
        meta: { title: 'POC管理', icon: 'Aim' }
      },
      {
        path: 'fingerprint',
        name: 'Fingerprint',
        component: () => import('@/views/Fingerprint.vue'),
        meta: { title: '指纹管理', icon: 'Stamp' }
      },
      {
        path: 'report',
        name: 'Report',
        component: () => import('@/views/Report.vue'),
        meta: { title: '扫描报告', icon: 'Document', hidden: true }
      },
      {
        path: 'user',
        name: 'User',
        redirect: '/settings?tab=user',
        meta: { title: '用户管理', icon: 'User', roles: ['superadmin'], hidden: true }
      },
      {
        path: 'organization',
        name: 'Organization',
        redirect: '/settings?tab=organization',
        meta: { title: '组织管理', icon: 'OfficeBuilding', hidden: true }
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/Settings.vue'),
        meta: { title: '系统配置', icon: 'Setting' }
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫
router.beforeEach((to, from, next) => {
  const userStore = useUserStore()
  
  if (to.meta.requiresAuth !== false && !userStore.token) {
    next('/login')
  } else if (to.path === '/login' && userStore.token) {
    next('/dashboard')
  } else {
    next()
  }
})

export default router
