<template>
  <section class="container mt-5">
    <div class="row g-4">
      <!-- 漏洞类型分布 -->
      <div class="col-md-6">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-chart-bar me-2"></i>
            <span>漏洞类型分布</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="typeChartRef" />
          </div>
        </div>
      </div>

      <!-- 历史漏洞趋势 -->
      <div class="col-md-6">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-chart-line me-2"></i>
            <span>历史漏洞趋势</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="trendChartRef" />
          </div>
        </div>
      </div>
      <!-- 漏洞列表 -->
      <div class="row">
        <div class="col-12">
          <div class="card">
            <div class="card-header d-flex align-items-center">
              <i class="fas fa-list me-2" />
              <span>CVE漏洞检测结果</span>
            </div>
            <div class="card-body">
              <div class="d-flex justify-content-between mb-3">
                <div>
                  <div class="vulnerability-progress w-100 mb-2">
                    <div
                      class="progress-bar progress-bar-safe"
                      style="width: 85%"
                    />
                    <div
                      class="progress-bar progress-bar-vulnerable"
                      style="width: 15%"
                    />
                  </div>
                  <div class="d-flex">
                    <div class="me-3">
                      <span class="badge bg-success me-1">■</span> 平均防护率: 85%
                    </div>
                    <div>
                      <span class="badge bg-danger me-1">■</span> 存在风险: 15%
                    </div>
                  </div>
                </div>
                <div>
                  <input
                    v-model="search"
                    type="text"
                    class="form-control"
                    placeholder="搜索CVE..."
                  />
                </div>
              </div>

              <div class="table-responsive">
                <table class="table table-hover">
                  <thead>
                    <tr>
                      <th>CVE 编号</th>
                      <th>漏洞名称</th>
                      <th>防护机器数</th>
                      <th>防护率</th>
                      <th>CVSS 评分</th>
                      <th>详情</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="vuln in filteredCveData"
                      :key="vuln.cve"
                    >
                      <td><strong>{{ vuln.cve }}</strong></td>
                      <td>{{ vuln.name }}</td>
                      <td>
                        <span class="badge bg-info">{{ vuln.protected }}/{{
                          vuln.total
                        }}</span>
                      </td>
                      <td>
                        <span
                          class="badge"
                          :class="protectionBadgeClass(vuln.protectionRate)"
                          >{{ vuln.protectionRate }}%</span
                        >
                      </td>
                      <td>
                        <span
                          class="badge"
                          :class="cvssBadgeClass(vuln.cvss)"
                          >{{ vuln.cvss }}</span
                        >
                      </td>
                      <td>{{ vuln.detail }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Chart, registerables } from 'chart.js'
Chart.register(...registerables)

// Refs
const typeChartRef = ref(null)
const trendChartRef = ref(null)
const cpuVendorChartRef = ref(null)


// ==== CVE 数据 ====

const search = ref('')
const filteredCveData = computed(() =>
  cveData.filter((v) => v.cve.includes(search.value) || v.name.includes(search.value))
)

const cveDataRaw = [
  { cve: "CVE-2017-5753", name: "Spectre V1", protected: 6, total: 6, cvss: 5.6 ,detail: 'Spectre变体1 (边界检查绕过)'},
  { cve: "CVE-2017-5715", name: "Spectre V2", protected: 5, total: 6, cvss: 5.9 ,detail: 'Spectre变体2 (分支目标注入)'},
  { cve: "CVE-2017-5754", name: "Meltdown", protected: 6, total: 6, cvss: 5.6 ,detail: 'Meltdown (恶意数据缓存加载)'},
  { cve: "CVE-2018-3639", name: "Spectre V4", protected: 5, total: 6, cvss: 5.6 ,detail: '变体3A (恶意系统寄存器读取)'},
  { cve: "CVE-2018-3640", name: "Spectre V3A", protected: 5, total: 6, cvss: 4.3 ,detail: '变体4 (推测存储绕过)'},
  { cve: "CVE-2018-3615", name: "L1TF SGX", protected: 6, total: 6, cvss: 5.6 ,detail: 'L1TF SGX (L1终端故障 - SGX)'},
  { cve: "CVE-2018-3620", name: "L1TF OS", protected: 6, total: 6, cvss: 5.6 ,detail: 'L1TF OS (L1终端故障 - 操作系统)'},
  { cve: "CVE-2018-3646", name: "L1TF VMM", protected: 6, total: 6, cvss: 5.6 ,detail: 'L1TF VMM (L1终端故障 - 虚拟机监视器)'},
  { cve: "CVE-2018-12126", name: "MSBDS", protected: 4, total: 6, cvss: 6.5 ,detail: 'MSBDS (微架构存储缓冲区数据采样)'},
  { cve: "CVE-2018-12130", name: "MFBDS", protected: 5, total: 6, cvss: 6.5 ,detail: 'MFBDS (微架构填充缓冲区数据采样)'},
  { cve: "CVE-2018-12127", name: "MLPDS", protected: 5, total: 6, cvss: 6.5 ,detail: 'MLPDS (微架构加载端口数据采样)'},
  { cve: "CVE-2019-11091", name: "MDSUM", protected: 5, total: 6, cvss: 3.8 ,detail: 'MDSUM (微架构数据采样无缓存内存)'},
  { cve: "CVE-2019-11135", name: "TAA", protected: 5, total: 6, cvss: 6.5 ,detail: 'TAA (TSX异步中止)'},
  { cve: "CVE-2018-12207", name: "ITLBMH", protected: 6, total: 6, cvss: 6.5 ,detail: 'ITLBMH (指令TLB多级页表)'},
  { cve: "CVE-2020-0543", name: "SRBDS", protected: 6, total: 6, cvss: 6.5 ,detail: 'SRBDS (特殊寄存器缓冲区数据采样)'},
  { cve: "CVE-2023-20593", name: "Zenbleed", protected: 6, total: 6, cvss: 6.5 ,detail: 'Zenbleed (AMD Zen2架构漏洞)'},
  { cve: "CVE-2022-40982", name: "Downfall", protected: 6, total: 6, cvss: 6.5 ,detail: 'Downfall (收集数据采样)'},
  { cve: "CVE-2022-4543", name: "Entrybleed", protected: 5, total: 6, cvss: 7.0 ,detail: 'EntryBleed (KASLR绕过)'},
  { cve: "CVE-2023-20569", name: "Inception", protected: 5, total: 6, cvss: 4.7 ,detail: 'Inception (AMD推测执行漏洞)'},
  { cve: "CVE-2023-23583", name: "Reptar", protected: 6, total: 6, cvss: 8.8 ,detail: 'Reptar (Intel序列化指令漏洞)'}
]
// 计算样式工具
function protectionBadgeClass(rate) {
  if (rate === 100) return 'bg-success'
  if (rate >= 80) return 'bg-warning text-dark'
  return 'bg-danger'
}
function cvssBadgeClass(score) {
  if (score >= 7.0) return 'bg-danger'
  if (score >= 4.0) return 'bg-warning text-dark'
  return 'bg-primary'
}
function riskBadgeClass(status) {
  return {
    danger: 'bg-danger',
    warning: 'bg-warning text-dark',
    success: 'bg-success'
  }[status]
}
function riskCountBadgeClass(count) {
  return count >= 4 ? 'bg-danger' : 'bg-warning'
}
function riskLevelBadgeClass(count) {
  return count >= 4 ? 'bg-danger' : 'bg-warning text-dark'
}
// 追加计算字段
const cveData = cveDataRaw.map((v) => ({
  ...v,
  protectionRate: Math.round((v.protected / v.total) * 100)
}))

onMounted(() => {
  // 漏洞类型分布
  new Chart(typeChartRef.value.getContext('2d'), {
    type: 'bar',
    data: {
      labels: ['推测执行漏洞', '侧信道攻击', '缓存攻击', '其他硬件漏洞'],
      datasets: [
        {
          label: '漏洞数量',
          data: [8, 6, 4, 2],
          backgroundColor: ['#283593', '#5c6bc0', '#ff4081', '#ffc107']
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: {
          display: true,
          text: '基于20个CVE漏洞的类型分析'
        }
      }
    }
  })

  // 历史漏洞趋势
  new Chart(trendChartRef.value.getContext('2d'), {
    type: 'line',
    data: {
      labels: ['6/10', '6/11', '6/12', '6/13', '6/14', '6/15'],
      datasets: [
        {
          label: '每日检测机器数',
          data: [1, 2, 3, 4, 5, 6],
          borderColor: '#283593',
          backgroundColor: 'rgba(40, 53, 147, 0.1)',
          fill: true,
          tension: 0.4
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        title: { display: true, text: '机器检测报告提交趋势' }
      }
    }
  })
})
</script>


