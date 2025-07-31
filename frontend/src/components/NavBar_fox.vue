<template>
  <nav class="navbar navbar-expand-lg navbar-dark sticky-top nav-gradient">
    <div class="container">
      <!-- Logo -->
      <RouterLink to="/" class="navbar-brand d-flex align-items-center">
        <i class="fas fa-bomb fa-2x me-2" aria-hidden="true" />
        <span class="fw-bold">SpecProbe-Attack</span>
      </RouterLink>

      <!-- Collapse button (mobile) -->
      <button
        class="navbar-toggler"
        type="button"
        data-bs-toggle="collapse"
        data-bs-target="#navMain"
      >
        <span class="navbar-toggler-icon" />
      </button>

      <!-- Links -->
      <div class="collapse navbar-collapse" id="navMain">
        <ul class="navbar-nav ms-auto">
          <li
            v-for="item in nav"
            :key="item.path"
            class="nav-item"
          >
            <RouterLink
              :to="item.path"
              class="nav-link d-flex align-items-center"
              active-class="active fw-bold"
              exact
            >
              <i :class="[item.icon, 'me-1']" /> {{ item.label }}
            </RouterLink>
          </li>
        </ul>
      </div>
    </div>
  </nav>
</template>

<script setup>
// 顶栏导航配置
const nav = [
  { path: '/', label: '首页', icon: 'fas fa-home' },
  { path: '/upload', label: '上传报告', icon: 'fas fa-upload' },
  { path: '/reports', label: '报告列表', icon: 'fas fa-list' },
  { path: '/charts', label: '分析图表', icon: 'fas fa-chart-bar' },
  { path: '/settings', label: '设置', icon: 'fas fa-cog' }
]
</script>

<style scoped>
.navbar {
    background: linear-gradient(to right, #e65100, #ffa726);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
</style>

