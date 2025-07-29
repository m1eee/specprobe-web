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

      <!-- CPU 厂商分布 -->
      <div class="col-md-12">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-chart-pie me-2"></i>
            <span>CPU厂商分布</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="cpuVendorChartRef" />
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Chart, registerables } from 'chart.js'
Chart.register(...registerables)

// Refs
const typeChartRef = ref(null)
const trendChartRef = ref(null)
const cpuVendorChartRef = ref(null)

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

  // CPU 厂商分布
  new Chart(cpuVendorChartRef.value.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Intel', 'AMD'],
      datasets: [
        {
          data: [4, 2],
          backgroundColor: ['#0d6efd', '#dc3545'],
          borderWidth: 3,
          borderColor: '#fff'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            padding: 20,
            font: { size: 14, weight: 'bold' },
            generateLabels: (chart) => {
              const data = chart.data
              const total = data.datasets[0].data.reduce((a, b) => a + b, 0)
              return data.labels.map((label, i) => {
                const value = data.datasets[0].data[i]
                const pct = ((value / total) * 100).toFixed(1)
                return {
                  text: `${label}: ${value}台 (${pct}%)`,
                  fillStyle: data.datasets[0].backgroundColor[i],
                  strokeStyle: data.datasets[0].borderColor,
                  lineWidth: data.datasets[0].borderWidth,
                  hidden: false,
                  index: i
                }
              })
            }
          }
        },
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0)
              const pct = ((ctx.raw / total) * 100).toFixed(1)
              return `${ctx.label}: ${ctx.raw}台 (${pct}%)`
            },
            afterLabel: (ctx) => {
              const map = {
                Intel: [
                  'A机(i5‑12500H)',
                  'C机(i9‑14900HX)',
                  'D机(i7‑10870H)',
                  'F机(i5‑12500H)'
                ],
                AMD: ['B机(R7‑6800HS)', 'E机(R7‑6800S)']
              }
              return map[ctx.label] ?? []
            }
          }
        },
        title: {
          display: true,
          text: '基于6台检测机器的CPU厂商分布',
          font: { size: 16, weight: 'bold' },
          padding: { bottom: 20 }
        }
      },
      cutout: '50%'
    }
  })
})
</script>


