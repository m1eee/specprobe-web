<template>
  <nav class="navbar navbar-expand-lg navbar-dark sticky-top nav-gradient">
    <div class="container">
      <RouterLink to="/" class="navbar-brand d-flex align-items-center">
        <i class="fas fa-shield-alt fa-2x me-2" />
        <span class="fw-bold">SpecProbe</span>
      </RouterLink>

      <button
        class="navbar-toggler"
        type="button"
        data-bs-toggle="collapse"
        data-bs-target="#navMain"
      >
        <span class="navbar-toggler-icon" />
      </button>

      <div class="collapse navbar-collapse" id="navMain">
        <ul class="navbar-nav ms-auto">
          <template v-for="item in nav" :key="item.label">
            <li v-if="!item.children" class="nav-item">
              <RouterLink
                :to="item.path"
                class="nav-link d-flex align-items-center"
                :active-class="item.exact ? '' : 'active fw-bold'"
                :exact-active-class="item.exact ? 'active fw-bold' : ''"
              >
                <i :class="[item.icon, 'me-1']" /> {{ item.label }}
              </RouterLink>
            </li>

            <li v-else class="nav-item dropdown">
              <a
                class="nav-link dropdown-toggle d-flex align-items-center"
                href="#"
                role="button"
                data-bs-toggle="dropdown"
                aria-expanded="false"
              >
                <i :class="[item.icon, 'me-1']" /> {{ item.label }}
              </a>
              <ul class="dropdown-menu">
                <li v-for="child in item.children" :key="child.path">
                  <RouterLink :to="child.path" class="dropdown-item" active-class="active">
                    {{ child.label }}
                  </RouterLink>
                </li>
              </ul>
            </li>
          </template>
        </ul>
      </div>
    </div>
  </nav>
</template>

<script setup>
// 顶栏导航配置
const nav = [
  { path: '/', label: '首页', icon: 'fas fa-home', exact: true },
  { path: '/upload', label: '上传报告', icon: 'fas fa-upload' },
  { path: '/reports', label: '报告列表', icon: 'fas fa-list' },
  {
    label: '分析图表',
    icon: 'fas fa-chart-bar',
    children: [
      { path: '/charts1', label: '企业分析图表' },
      { path: '/charts2', label: '芯片/系统分析图表' },
    ],
  },
  { path: '/settings', label: '设置', icon: 'fas fa-cog' },
]
</script>

