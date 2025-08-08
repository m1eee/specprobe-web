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


    </div>
  </nav>
</template>
<script setup>
</script>

<style scoped>
.navbar {
    background: linear-gradient(to right, #e65100, #ffa726);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
</style>