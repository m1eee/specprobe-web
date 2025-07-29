<template>
  <section class="container py-5">
    <div class="card">
      <div class="card-header d-flex align-items-center">
        <i class="fas fa-cloud-upload-alt me-2"></i>
        <span>上传漏洞检测报告</span>
      </div>
      <div class="card-body">
        <!-- 成功提示 -->
        <div v-if="success" class="alert alert-success">
          <i class="fas fa-check-circle me-2"></i>
          报告上传成功！系统正在分析检测结果...
        </div>

        <!-- 上传区域 -->
        <div
          class="upload-area text-center my-4"
          @dragover.prevent
          @drop.prevent="handleDrop"
        >
          <i class="fas fa-file-upload fa-3x text-primary mb-3"></i>
          <h4>拖放检测报告文件到此处</h4>
          <p class="text-muted mb-3">支持 JSON 格式的漏洞检测报告</p>

          <!-- 隐藏文件选择 -->
          <input
            ref="fileInput"
            type="file"
            accept="application/json"
            hidden
            @change="handleSelect"
          />
          <button class="btn btn-primary px-4" @click="triggerSelect">
            <i class="fas fa-folder-open me-2"></i>选择文件
          </button>
        </div>

        <!-- 使用说明 -->
        <div class="mt-4">
          <h5>
            <i class="fas fa-info-circle me-2 text-primary"></i>使用说明
          </h5>
          <ol>
            <li>下载并运行本地漏洞检测工具</li>
            <li>工具运行完成后导出检测报告(JSON格式)</li>
            <li>在此处上传生成的报告文件</li>
            <li>系统将自动分析并展示检测结果</li>
          </ol>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import axios from 'axios'

const success = ref(false)
const fileInput = ref(null)

function triggerSelect() {
  fileInput.value?.click()
}

function handleSelect(e) {
  const file = e.target.files[0]
  uploadFile(file)
}

function handleDrop(e) {
  const file = e.dataTransfer.files[0]
  uploadFile(file)
}

async function uploadFile(file) {
  if (!file) return
  if (file.type !== 'application/json' && !file.name.endsWith('.json')) {
    alert('只支持 JSON 格式的检测报告')
    return
  }
  const form = new FormData()
  form.append('file', file)
  try {
    await axios.post('/api/import-report/', form, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    const { data } = await axios.post('/api/import-report/', form, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    console.log('[import-report] result:', data) 
    success.value = true
  } catch (err) {
    console.error(err)
    alert('上传失败，请重试')
  }
}
</script>


