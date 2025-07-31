<template>
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

    <!-- 图表展示区域 -->
    <div class="row mb-4">
        <div class="col-md-6">
          <div class="card system-card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-chart-pie me-2"></i>
            <span>CPU厂商分布</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="cpuVendorCanvas" />
          </div>
        </div>
      </div>

      <div class="col-md-6">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-shield-alt me-2" />
            <span>系统安全状态</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="securityStatusCanvas" />
          </div>
        </div>
      </div>
    </div>

    <!-- 系统信息 -->
    <div class="row mb-4">
      <div class="col-md-12">
        <div class="card system-card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-desktop me-2" />
            <span>检测系统概览</span>
          </div>
          <div class="card-body">
            <div class="row">
              <div
                class="col-md-4 mb-3"
                v-for="machine in machines"
                :key="machine.name"
              >
                <div class="card border-0 bg-light">
                  <div class="card-body p-3">
                    <div
                      class="d-flex justify-content-between align-items-start mb-2"
                    >
                      <h6 class="card-title mb-0">{{ machine.name }}</h6>
                      <span
                        v-if="machine.risk_count > 0"
                        class="badge bg-danger"
                        >{{ machine.risk_count }}个风险</span
                      >
                      <span v-else class="badge bg-success">安全</span>
                    </div>
                    <div class="small text-muted">
                      <div class="mb-1">
                        <i class="fas fa-microchip me-1 text-primary" />{{
                          machine.cpu
                        }}
                      </div>
                      <div class="mb-1">
                        <i class="fab fa-linux me-1 text-success" />{{ machine.os }}
                      </div>
                      <div>
                        <i class="fas fa-code-branch me-1 text-info" />{{
                          machine.kernel
                        }}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- CPU/内核比较图表 -->
    <div class="row mt-4">
      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-exchange-alt me-2" />
            <span>不同CPU/内核漏洞比较</span>
          </div>
          <div class="card-body">
            <div class="chart-container">
              <canvas ref="comparisonCanvas" />
            </div>

            <!-- 修改后的表格容器 -->
            <div class="table-responsive mt-4 cpu-kernel-scroll">
              <table
                class="table table-bordered cpu-kernel-table"
                style="min-width: 1200px"
              >
                <thead>
                  <tr>
                    <th>机器MAC</th>
                    <th>CPU 型号</th>
                    <th>操作系统</th>
                    <th>内核版本</th>
                    <th>检测CVE数</th>
                    <th>风险漏洞数</th>
                    <th>风险等级</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="row in comparisonTable" :key="row.mac">
                    <td>{{ row.mac }}</td>
                    <td>{{ row.cpu }}</td>
                    <td>{{ row.os }}</td>
                    <td>{{ row.kernel }}</td>
                    <td>
                      <span class="badge bg-primary">{{ row.vuln_count }}</span>
                    </td>
                    <td>
                      <span
                        :class="['badge', riskCountBadgeClass(row.risk_count)]"
                        >{{ row.risk_count }}</span
                      >
                    </td>
                    <td>
                      <span
                        :class="['badge', riskLevelBadgeClass(row.risk_level)]"
                        >{{ row.riskLevel }}</span
                      >
                    </td>
                  </tr>
                </tbody>
              </table>
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
import axios  from 'axios'
Chart.register(...registerables)

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


function riskCountBadgeClass(count) {
  return count >= 4 ? 'bg-danger' : 'bg-warning'
}
function riskLevelBadgeClass(count) {
  return count >= 4 ? 'bg-danger' : 'bg-warning text-dark'
}

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

