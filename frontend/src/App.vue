<template>
  <NavBar />
  <router-view/>
  <Footer />
</template>

<script setup>
import NavBar from '@/components/NavBar.vue'
import Footer from '@/components/Footer.vue'
</script>