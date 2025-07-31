<template>
  <Header />
  <router-view />
  <Footer />
</template>
<script setup lang="ts">
import Header from '@/components/NavBar.vue'
import Footer from '@/components/Footer.vue'
</script>
