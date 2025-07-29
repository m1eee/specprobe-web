<template>
  <section class="container mt-5">
    <div class="card">
      <div class="card-header d-flex align-items-center">
        <i class="fas fa-cog me-2" />
        <span>账户设置</span>
      </div>
      <div class="card-body">
        <form @submit.prevent="saveSettings">
          <div class="row g-4">
            <!-- 通知设置 -->
            <div class="col-md-6">
              <div class="card system-card h-100">
                <div class="card-header">通知设置</div>
                <div class="card-body">
                  <div class="form-check form-switch mb-3">
                    <input
                      class="form-check-input"
                      type="checkbox"
                      id="notifSwitch"
                      v-model="form.notifications"
                    />
                    <label class="form-check-label" for="notifSwitch">
                      接收系统通知
                    </label>
                  </div>
                  <div class="form-check form-switch mb-3">
                    <input
                      class="form-check-input"
                      type="checkbox"
                      id="autoSwitch"
                      v-model="form.auto_analyze"
                    />
                    <label class="form-check-label" for="autoSwitch">
                      自动分析新报告
                    </label>
                  </div>
                  <label class="form-label">通知方式</label>
                  <div v-for="alert in alertOptions" :key="alert" class="form-check">
                    <input
                      type="checkbox"
                      class="form-check-input"
                      :id="`alert-${alert}`"
                      :value="alert"
                      v-model="form.alerts"
                    />
                    <label class="form-check-label" :for="`alert-${alert}`">
                      {{ alert.charAt(0).toUpperCase() + alert.slice(1) }}
                    </label>
                  </div>
                </div>
              </div>
            </div>
            <!-- 账户安全 -->
            <div class="col-md-6">
              <div class="card system-card h-100">
                <div class="card-header">账户安全</div>
                <div class="card-body">
                  <div class="mb-3">
                    <label class="form-label">当前语言</label>
                    <select v-model="form.language" class="form-select">
                      <option value="zh-CN">简体中文</option>
                      <option value="en-US">English</option>
                    </select>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">API 密钥</label>
                    <input
                      type="text"
                      class="form-control"
                      :value="form.api_key"
                      readonly
                    />
                  </div>
                  <button type="button" class="btn btn-outline-primary" @click="resetKey">
                    <i class="fas fa-key me-2" />重置API密钥
                  </button>
                </div>
              </div>
            </div>
          </div>
          <!-- 保存按钮 -->
          <div class="d-flex justify-content-end mt-4">
            <button class="btn btn-primary px-5" type="submit">
              保存设置
            </button>
          </div>
        </form>
      </div>
    </div>
  </section>
</template>

<script setup>
import { reactive, onMounted } from 'vue'
import axios from 'axios'

const form = reactive({
  notifications: false,
  auto_analyze: false,
  alerts: [],
  language: 'zh-CN',
  api_key: ''
})

const alertOptions = ['email', 'sms', 'wechat']

async function fetchSettings() {
  try {
    const { data } = await axios.get('/api/settings/')
    Object.assign(form, data)
  } catch (err) {
    console.error(err)
  }
}

async function saveSettings() {
  try {
    await axios.post('/api/settings/', form)
    alert('设置已保存')
  } catch (err) {
    console.error(err)
    alert('保存失败')
  }
}

async function resetKey() {
  try {
    const { data } = await axios.post('/api/settings/reset-key')
    form.api_key = data.api_key
    alert('已生成新 API 密钥')
  } catch (err) {
    console.error(err)
    alert('重置失败')
  }
}

onMounted(fetchSettings)
</script>

<style scoped>
.system-card {
  border: 1px solid #e3e6f0;
  border-radius: 0.5rem;
}
</style>
