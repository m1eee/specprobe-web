<template>
  <!-- ——————————— 网站介绍弹窗 ——————————— -->
  <div
    class="modal fade"
    id="introModal"
    tabindex="-1"
    ref="introModal"
    aria-labelledby="introModalLabel"
    aria-hidden="true"
  >
    <div class="modal-dialog modal-dialog-centered modal-xl">
      <div class="modal-content shadow-lg border-0">
        <div class="card-header bg-primary text-white d-flex align-items-center justify-content-between">
          <h5 class="modal-title" id="introModalLabel">
            <i class="fas fa-rocket me-2"></i>欢迎使用 CPU 漏洞检测与分析平台
          </h5>
          <button
            type="button"
            class="btn-close btn-close-white"
            @click="closeIntro"
            aria-label="Close"
          ></button>
        </div>

        <div class="modal-body p-4">
          <p class="lead text-center mb-4">
            一个集本地扫描、报告上传、数据可视化与深度分析于一体的安全平台。
          </p>

          <h5 class="fw-bold mb-3 text-center">
            <i class="fas fa-project-diagram me-2"></i>简明工作流
          </h5>
          <div class="row text-center mb-5">
            <div class="col-md-4">
              <div class="p-3">
                <div
                  class="icon-circle bg-light text-primary mx-auto mb-3"
                >
                  <i class="fas fa-download fa-2x"></i>
                </div>
                <h6 class="fw-bold">1. 下载并检测</h6>
                <p class="small text-muted">
                  下载本地扫描工具，对您的目标机器进行一键扫描，生成包含硬件信息的
                  <code>JSON</code> 格式报告。
                </p>
              </div>
            </div>
            <div class="col-md-4">
              <div class="p-3">
                 <div
                  class="icon-circle bg-light text-primary mx-auto mb-3"
                >
                  <i class="fas fa-upload fa-2x"></i>
                </div>
                <h6 class="fw-bold">2. 上传与分析</h6>
                <p class="small text-muted">
                  将生成的报告文件上传至本平台。系统将自动解析数据，分析每一个机器面临的
                  <code>CVE</code> 风险状态。
                </p>
              </div>
            </div>
            <div class="col-md-4">
              <div class="p-3">
                 <div
                  class="icon-circle bg-light text-primary mx-auto mb-3"
                >
                  <i class="fas fa-chart-pie fa-2x"></i>
                </div>
                <h6 class="fw-bold">3. 汇总与分析</h6>
                <p class="small text-muted">
                  汇总所有机器的检测结果，并通过丰富的可视化图表和报告洞察风险，根据平台的建议对存在风险的系统进行安全加固。
                </p>
              </div>
            </div>
          </div>

          <h5 class="fw-bold mb-3 text-center">
             <i class="fas fa-star me-2"></i>核心功能一览
          </h5>
          <div class="row">
            <div class="col-lg-6">
              <ul class="list-group list-group-flush">
                <li class="list-group-item d-flex align-items-start border-0">
                  <i class="fas fa-tachometer-alt fa-fw text-primary me-3 mt-1"></i>
                  <div>
                    <h6 class="fw-bold mb-0">全局统计仪表盘</h6>
                    <small>直观展示已检测机器总数、风险主机与安全主机的分布情况。</small>
                  </div>
                </li>
                <li class="list-group-item d-flex align-items-start border-0">
                   <i class="fas fa-chart-bar fa-fw text-primary me-3 mt-1"></i>
                  <div>
                    <h6 class="fw-bold mb-0">多维度可视化分析</h6>
                    <small>提供漏洞类型、CPU厂商、历史趋势等多种图表，深入分析漏洞数据。</small>
                  </div>
                </li>
                 <li class="list-group-item d-flex align-items-start border-0">
                  <i class="fas fa-list-ul fa-fw text-primary me-3 mt-1"></i>
                  <div>
                    <h6 class="fw-bold mb-0">CVE 防护详情</h6>
                    <small>详细列出每个CVE的防护率、CVSS评分和受影响机器，并用颜色标记风险等级。</small>
                  </div>
                </li>
              </ul>
            </div>
            <div class="col-lg-6">
               <ul class="list-group list-group-flush">
                <li class="list-group-item d-flex align-items-start border-0">
                  <i class="fas fa-desktop fa-fw text-primary me-3 mt-1"></i>
                  <div>
                    <h6 class="fw-bold mb-0">历史与设备报告</h6>
                    <small>管理所有上传的历史报告，并可查看任一设备的具体漏洞详情。</small>
                  </div>
                </li>
                <li class="list-group-item d-flex align-items-start border-0">
                  <i class="fas fa-filter fa-fw text-primary me-3 mt-1"></i>
                  <div>
                    <h6 class="fw-bold mb-0">强大的筛选与排序</h6>
                    <small>在报告页面，可根据MAC地址、CPU、内核版本等任意关键字进行快速搜索和排序。</small>
                  </div>
                </li>
                <li class="list-group-item d-flex align-items-start border-0">
                   <i class="fas fa-lightbulb fa-fw text-primary me-3 mt-1"></i>
                  <div>
                    <h6 class="fw-bold mb-0">提供操作建议</h6>
                    <small>根据分析结果，平台会自动生成可行的操作建议，辅助您进行安全决策。</small>
                  </div>
                </li>
              </ul>
            </div>
          </div>
          
           <div class="alert alert-info mt-4 mb-0" role="alert">
             <i class="fas fa-shield-alt me-2"></i>
             <strong class="me-2">数据安全承诺:</strong>本平台仅用于企业内部安全评估，所有检测数据均存储于专用服务器，确保您的数据隐私与合规。
          </div>
        </div>

        <div class="modal-footer">
          <button class="btn btn-primary px-4" @click="closeIntro">
            <i class="fas fa-arrow-right me-2"></i>立即开始
          </button>
        </div>
      </div>
    </div>
  </div>
  <!-- 仪表盘头部 -->
  <section class="dashboard-header">
    <div class="container text-center">
      <h1 class="display-4 fw-bold mb-3">漏洞检测与分析平台</h1>
      <p class="lead mb-4">检测、分析并可视化您的系统漏洞状态</p>
      <div class="d-flex justify-content-center gap-3">
        <!-- 下载工具按钮 -->
        <a
          class="btn btn-light btn-lg px-4 py-2 fw-bold"
          :href="toolLink"
          download
        >
          <i class="fas fa-download me-2" />下载检测工具
        </a>
        <!-- 上传报告按钮 -->
        <RouterLink
          to="/upload"
          class="btn btn-outline-light btn-lg px-4 py-2 fw-bold"
        >
          <i class="fas fa-upload me-2" />上传检测报告
        </RouterLink>
      </div>
    </div>
  </section>

  <main class="container mb-5">
    <!-- 统计卡片 -->
    <div class="row mb-4">
      <div class="col-md-3" v-for="stat in stats" :key="stat.label">
        <div class="card stat-card">
          <div class="stat-icon">
            <i :class="stat.icon" />
          </div>
          <h3 class="stat-number">{{ stat.value }}</h3>
          <p class="text-muted">{{ stat.label }}</p>
        </div>
      </div>
    </div>

    <!-- 上传区域 -->
    <div class="row mb-5">
      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-cloud-upload-alt me-2" />
            <span>上传漏洞检测报告</span>
          </div>
          <div class="card-body">
            <div class="upload-area text-center">
              <i class="fas fa-file-upload fa-3x text-primary mb-3" />
              <h4>拖放检测报告文件到此处</h4>
              <p class="text-muted mb-3">支持JSON格式的漏洞检测报告</p>
              <RouterLink to="/upload" class="btn btn-primary px-4">
                <i class="fas fa-folder-open me-2" />选择文件
              </RouterLink>
            </div>
            <div class="mt-4">
              <h5>
                <i class="fas fa-info-circle me-2 text-primary" />使用说明
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
      </div>
    </div>
  </main>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Chart, registerables } from 'chart.js'
import { Modal } from 'bootstrap' 
import axios  from 'axios'
Chart.register(...registerables)

// —— 介绍弹窗逻辑 ——
const introModal = ref(null)      // 绑定模板的 ref
let introInstance = null          // 保存 Modal 实例

function closeIntro() {
  introInstance?.hide()
}

onMounted(() => {
  // 自动弹出；如需“仅首次弹出”，见下方可选写法
  introInstance = new Modal(introModal.value, {
    backdrop: 'static',           // 禁止点击遮罩关闭
    keyboard: false               // 禁止 Esc 关闭
  })
  // 检查会话存储中是否已有标志
  if (!sessionStorage.getItem('hasSeenIntro')) {
    // 如果没有标志，说明是此会话的首次加载
    // 1. 显示弹窗
    introInstance.show()

    // 2. 在会话存储中设置标志，以便刷新后不再弹出
    sessionStorage.setItem('hasSeenIntro', 'true')
  }
})

// Props or API data placeholders
const toolLink = '/static/packages/CPUVulnerabilityScanner.AppImage'

const machines = ref([])

// 统计信息
const stats = computed(() => {
  const rows   = machines.value                      // 数组
  const total  = rows.length                         // 检测的机器数量
  const risky  = rows.filter(r => Number(r.risk_count) > 0).length // risk_count>0
  const safe   = total - risky                       // 安全的机器 = 剩余

  return [
    { icon: 'fas fa-bug', value: 20, label: '检测的CVE漏洞' },
    { icon: 'fas fa-shield-alt',          value: safe,  label: '安全的机器' },
    { icon: 'fas fa-exclamation-triangle', value: risky, label: '存在风险的机器' },
    { icon: 'fas fa-microchip',           value: total, label: '检测的机器数量' }
  ]
})


// Charts
const cpuVendorCanvas = ref(null)
const securityStatusCanvas = ref(null)
const comparisonCanvas = ref(null)

const comparisonTable = ref([])
const fetchData = async () => {
  try {
    const res = await axios.get('/api/reports/')
    comparisonTable.value = (res.data.machines ?? []).map(m => {
      const row = { ...m }
      row.riskLevel  = m.risk_count >= 5 ? '高' : m.risk_count ? '中' : '低'
      return row
    })
    machines.value = res.data.machines
  } catch (e) {
    console.error(e)
  }
}

// 计算 CPU 厂商分布
const vendorCounts = computed(() => {
  const counts = { Intel: 0, AMD: 0, Other: 0 }
  machines.value.forEach(row => {
    console.log('Processing row:', row.cpu)
    const cpu = (row.cpu || '').toLowerCase()
    if (cpu.includes('intel')||cpu.includes('Intel')) counts.Intel++
    else if (cpu.includes('amd')||cpu.includes('AMD')) counts.AMD++
    else counts.Other++
  })
  console.log('Vendor counts:', counts)
  return counts        // {Intel: n, AMD: m, Other: k}
})

onMounted(async() => {
  await fetchData()
  // CPU Vendor chart
  new Chart(cpuVendorCanvas.value.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Intel', 'AMD' ,'其他'],
      datasets: [
        {
          data: [vendorCounts.value.Intel, vendorCounts.value.AMD, vendorCounts.value.Other],
          backgroundColor: ['#0d6efd', '#dc3545', '#6c757d'],
          borderWidth: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom'
        }
      },
      cutout: '60%'
    }
  })

  // Security Status chart
  new Chart(securityStatusCanvas.value.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['存在风险', '相对安全'],
      datasets: [
        {
          data: [4, 2],
          backgroundColor: ['#dc3545', '#198754'],
          borderWidth: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom' }
      },
      cutout: '60%'
    }
  })

  // Comparison chart
  new Chart(comparisonCanvas.value.getContext('2d'), {
    type: 'bar',
    data: {
      labels: comparisonTable.value.map((r) => `${r.mac}`),
      datasets: [
        {
          label: '安全',
          data: comparisonTable.value.map((r) => r.vuln_count - r.risk_count),
          backgroundColor: '#198754'
        },
        {
          label: '存在风险',
          data: comparisonTable.value.map((r) => r.risk_count),
          backgroundColor: '#dc3545'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: {
          stacked: true,
          beginAtZero: true,
          max: 20,
          ticks: { precision: 0 },
          title: { display: true, text: 'CVE漏洞数量' }
        }
      },
      plugins: {
        legend: { position: 'top' },
        title: { display: true, text: '各机器CVE防护状态对比' }
      }
    }
  })
})
</script>

