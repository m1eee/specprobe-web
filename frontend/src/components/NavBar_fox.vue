<template>
  <nav class="navbar-fox navbar-expand-lg sticky-top">
    <div class="container-fluid">
      <RouterLink to="/" class="navbar-brand d-flex align-items-center">
        <i class="fas fa-user-secret me-3" aria-hidden="true"></i>
        <span class="brand-text">&gt; SpecProbe::Attack-Vector</span>
      </RouterLink>
      <button
        class="navbar-toggler"
        type="button"
        data-bs-toggle="collapse"
        data-bs-target="#navMain"
        aria-controls="navMain"
        aria-expanded="false"
        aria-label="Toggle navigation"
      >
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navMain">
        </div>
    </div>
  </nav>
</template>

<script setup>
import { RouterLink } from 'vue-router';
</script>

<style scoped>
/* Ensure you have a link to a monospaced font, like Fira Code */
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;700&display=swap');

.navbar-fox {
  font-family: 'Fira Code', monospace;
  background-color: #000000; /* Near-black background */
  border-bottom: 1px solid #00ff41; /* Green accent border */
  box-shadow: 0 0 20px rgba(0, 255, 65, 0.25); /* Green glow effect */
  padding: 0.75rem 1.5rem;
}

.navbar-brand {
  color: #00ff41; /* Hacker green */
  font-size: 1.5rem;
  text-shadow: 0 0 5px rgba(0, 255, 65, 0.7);
  transition: color 0.3s ease, text-shadow 0.3s ease;
}

.navbar-brand:hover,
.navbar-brand:focus {
  color: #9effb8; /* Lighter green on hover/focus */
  text-shadow: 0 0 10px rgba(158, 255, 184, 0.8);
}

.brand-text {
  letter-spacing: 1px;
}

/* Style for the mobile navigation toggle button */
.navbar-toggler {
  border-color: rgba(0, 255, 65, 0.5);
}

.navbar-toggler-icon {
  background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 30 30'%3e%3cpath stroke='rgba(0, 255, 65, 0.8)' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/%3e%3c/svg%3e");
}
</style>