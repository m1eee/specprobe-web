<template>
  <section class="container mt-5">
    <h2 class="mb-4">历史检测结果</h2>

    <!-- 漏洞状态分布 -->
    <div class="chart-container mb-4">
      <h5 class="mb-3">漏洞状态分布</h5>
      <canvas ref="statusRef" />
    </div>

    <!-- CPU 类型分布 -->
    <div class="chart-container mb-4">
      <h5 class="mb-3">CPU 类型分布</h5>
      <canvas ref="cpuRef" />
    </div>

    <!-- CVSS 评分分布 -->
    <div class="chart-container mb-5">
      <h5 class="mb-3">CVSS 评分分布</h5>
      <canvas ref="cvssRef" />
    </div>

    <!-- 详细检测记录表 -->
    <h3 class="mt-5">详细检测记录</h3>
    <div class="table-responsive">
      <table class="table table-striped table-hover">
        <thead>
          <tr>
            <th>检测时间</th>
            <th>操作系统</th>
            <th>CPU 型号</th>
            <th>内核版本</th>
            <th>内存信息</th>
            <th>受影响漏洞数</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="sys in systems" :key="sys.id">
            <td>{{ sys.time }}</td>
            <td>{{ sys.os }}</td>
            <td>{{ sys.cpu }}</td>
            <td>{{ sys.kernel }}</td>
            <td>{{ sys.memory }}</td>
            <td :class="{'text-danger': sys.affected > 0}">{{ sys.affected }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Chart, registerables } from 'chart.js'
Chart.register(...registerables)

// refs
const statusRef = ref(null)
const cpuRef = ref(null)
const cvssRef = ref(null)

// mock systems data (后端替换)
const systems = ref([
  {
    id: 1,
    time: '2025-07-25 14:22',
    os: 'Ubuntu 22.04',
    cpu: 'Intel i5‑12500H',
    kernel: '6.8.0-60',
    memory: '16GB',
    affected: 2
  },
  {
    id: 2,
    time: '2025-07-26 10:05',
    os: 'Windows 11',
    cpu: 'AMD R7‑6800HS',
    kernel: '10.0.22631',
    memory: '32GB',
    affected: 0
  }
])

onMounted(() => {
  // 统计数据示例，可用后端接口替换
  const vulnStats = { 受影响: 5, 安全: 15 }
  const cpuStats = { Intel: 4, AMD: 2 }
  const cvssBuckets = { '0‑3.9': 4, '4‑6.9': 8, '7‑10': 2 }

  new Chart(statusRef.value.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(vulnStats),
      datasets: [
        {
          data: Object.values(vulnStats),
          backgroundColor: ['#dc3545', '#198754']
        }
      ]
    },
    options: {
      cutout: '55%',
      plugins: { legend: { position: 'bottom' } },
      maintainAspectRatio: false
    }
  })

  new Chart(cpuRef.value.getContext('2d'), {
    type: 'bar',
    data: {
      labels: Object.keys(cpuStats),
      datasets: [
        {
          label: '机器数量',
          data: Object.values(cpuStats),
          backgroundColor: ['#0d6efd', '#dc3545']
        }
      ]
    },
    options: {
      plugins: { legend: { display: false } },
      maintainAspectRatio: false
    }
  })

  new Chart(cvssRef.value.getContext('2d'), {
    type: 'pie',
    data: {
      labels: Object.keys(cvssBuckets),
      datasets: [
        {
          data: Object.values(cvssBuckets),
          backgroundColor: ['#198754', '#ffc107', '#dc3545']
        }
      ]
    },
    options: {
      plugins: { legend: { position: 'bottom' } },
      maintainAspectRatio: false
    }
  })
})
</script>

<style scoped>
.chart-container {
  box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1);
  padding: 2rem;
  border-radius: 10px;
  background: #fff;
  position: relative;
  width: 100%;
  height: 320px;
}
</style>
