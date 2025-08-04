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
                  <!-- 已防护 -->
                  <div
                    class="progress-bar progress-bar-safe"
                    :style="{ width: avgProtectionRate + '%' }"
                  />
                  <!-- 存在风险 -->
                  <div
                    class="progress-bar progress-bar-vulnerable"
                    :style="{ width: riskRate + '%' }"
                  />
                </div>
                <div class="d-flex">
                  <div class="me-3">
                    <span class="badge bg-success me-1">■</span>
                    平均防护率: {{ avgProtectionRate }}%
                  </div>
                  <div>
                    <span class="badge bg-danger me-1">■</span>
                    存在风险: {{ riskRate }}%
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
import { ref, computed, onMounted } from 'vue';
import { Chart, registerables } from 'chart.js';
import axios from 'axios';
Chart.register(...registerables);

// --- Refs ---
const typeChartRef = ref(null);
const trendChartRef = ref(null);
const search = ref('');

const cveStaticDetails = [
  { cve: "CVE-2017-5753", name: "Spectre V1", cvss: 5.6 ,detail: 'Spectre变体1 (边界检查绕过)'},
  { cve: "CVE-2017-5715", name: "Spectre V2", cvss: 5.9 ,detail: 'Spectre变体2 (分支目标注入)'},
  { cve: "CVE-2017-5754", name: "Meltdown", cvss: 5.6 ,detail: 'Meltdown (恶意数据缓存加载)'},
  { cve: "CVE-2018-3639", name: "Spectre V4", cvss: 5.6 ,detail: '变体3A (恶意系统寄存器读取)'},
  { cve: "CVE-2018-3640", name: "Spectre V3A", cvss: 4.3 ,detail: '变体4 (推测存储绕过)'},
  { cve: "CVE-2018-3615", name: "L1TF SGX", cvss: 5.6 ,detail: 'L1TF SGX (L1终端故障 - SGX)'},
  { cve: "CVE-2018-3620", name: "L1TF OS", cvss: 5.6 ,detail: 'L1TF OS (L1终端故障 - 操作系统)'},
  { cve: "CVE-2018-3646", name: "L1TF VMM", cvss: 5.6 ,detail: 'L1TF VMM (L1终端故障 - 虚拟机监视器)'},
  { cve: "CVE-2018-12126", name: "MSBDS", cvss: 6.5 ,detail: 'MSBDS (微架构存储缓冲区数据采样)'},
  { cve: "CVE-2018-12130", name: "MFBDS", cvss: 6.5 ,detail: 'MFBDS (微架构填充缓冲区数据采样)'},
  { cve: "CVE-2018-12127", name: "MLPDS", cvss: 6.5 ,detail: 'MLPDS (微架构加载端口数据采样)'},
  { cve: "CVE-2019-11091", name: "MDSUM", cvss: 3.8 ,detail: 'MDSUM (微架构数据采样无缓存内存)'},
  { cve: "CVE-2019-11135", name: "TAA", cvss: 6.5 ,detail: 'TAA (TSX异步中止)'},
  { cve: "CVE-2018-12207", name: "ITLBMH", cvss: 6.5 ,detail: 'ITLBMH (指令TLB多级页表)'},
  { cve: "CVE-2020-0543", name: "SRBDS", cvss: 6.5 ,detail: 'SRBDS (特殊寄存器缓冲区数据采样)'},
  { cve: "CVE-2023-20593", name: "Zenbleed", cvss: 6.5 ,detail: 'Zenbleed (AMD Zen2架构漏洞)'},
  { cve: "CVE-2022-40982", name: "Downfall", cvss: 6.5 ,detail: 'Downfall (收集数据采样)'},
  { cve: "CVE-2022-4543", name: "Entrybleed", cvss: 7.0 ,detail: 'EntryBleed (KASLR绕过)'},
  { cve: "CVE-2023-20569", name: "Inception", cvss: 4.7 ,detail: 'Inception (AMD推测执行漏洞)'},
  { cve: "CVE-2023-23583", name: "Reptar", cvss: 8.8 ,detail: 'Reptar (Intel序列化指令漏洞)'}
];


const cveData = ref([]);

const filteredCveData = computed(() =>
  cveData.value.filter((v) => v.cve.toLowerCase().includes(search.value.toLowerCase()) || v.name.toLowerCase().includes(search.value.toLowerCase()))
);


function protectionBadgeClass(rate) {
  if (rate === 100) return 'bg-success';
  if (rate >= 80) return 'bg-warning text-dark';
  return 'bg-danger';
}
function cvssBadgeClass(score) {
  if (score >= 7.0) return 'bg-danger';
  if (score >= 4.0) return 'bg-warning text-dark';
  return 'bg-primary';
}


async function fetchAndMergeCveData() {
  try {
    const response = await axios.get('/api/reports/'); 
    const fetchedVulnerabilities = response.data.vulnerabilities;
    console.log("Fetched vulnerabilities:", fetchedVulnerabilities);
    if (!fetchedVulnerabilities || !Array.isArray(fetchedVulnerabilities)) {
      console.error("Vulnerability data from API is not in the expected format.");
      cveData.value = [];
      return;
    }
    const staticInfoMap = new Map(cveStaticDetails.map(item => [item.cve, { name: item.name, cvss: item.cvss, detail: item.detail }]));
    const mergedData = fetchedVulnerabilities.map(vuln => {
      const staticInfo = staticInfoMap.get(vuln.cve) || {};
      const totalMachines = vuln.protected_count + vuln.affected_count + vuln.unknown_count;
      const protectionRate = totalMachines > 0 ? Math.round((vuln.protected_count / totalMachines) * 100) : 100;

      return {
        cve: vuln.cve,
        name: staticInfo.name || 'N/A',
        cvss: staticInfo.cvss || 0,
        detail: staticInfo.detail || 'No details available.',
        protected: vuln.protected_count,
        total: totalMachines,          
        protectionRate: protectionRate, 
      };
    });

    cveData.value = mergedData;

  } catch (error) {
    console.error("Failed to fetch CVE data:", error);
    cveData.value = []; 
  }
}

/**
 * @description Fetches report data and creates the historical trend chart.
 */
async function createTrendChart() {
  try {
    const response = await axios.get('/api/reports/');
    const machines = response.data.machines;
    if (!machines || !Array.isArray(machines)) {
      console.error("Machine data from API is not in the expected format:", machines);
      return;
    }
    const dailyCounts = {};
    for (const report of machines) {
      const date = report.report_time.split(' ')[0];
      dailyCounts[date] = (dailyCounts[date] || 0) + 1;
    }
    const sortedDates = Object.keys(dailyCounts).sort((a, b) => new Date(a) - new Date(b));
    const labels = sortedDates.map(date => {
        const d = new Date(date);
        return `${d.getUTCMonth() + 1}/${d.getUTCDate()}`;
    });
    const data = sortedDates.map(date => dailyCounts[date]);

    new Chart(trendChartRef.value.getContext('2d'), {
      type: 'line',
      data: { labels, datasets: [{
        label: '每日检测机器数', data, borderColor: '#283593', backgroundColor: 'rgba(40, 53, 147, 0.1)', fill: true, tension: 0.4,
      }]},
      options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: '机器检测报告提交趋势' }}},
    });
  } catch (error) {
    console.error("Failed to fetch or process trend data:", error);
  }
}

const avgProtectionRate = computed(() => {
  if (!cveData.value.length) return 0;            // 无数据兜底
  const total = cveData.value.reduce(
    (sum, item) => sum + item.protectionRate,
    0
  );
  return Math.round(total / cveData.value.length); // 0-100 的整数
});
const riskRate = computed(() => 100 - avgProtectionRate.value);


// Charts
const machines = ref([])
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

  new Chart(typeChartRef.value.getContext('2d'), {
    type: 'bar',
    data: {
      labels: ['推测执行漏洞', '侧信道攻击', '缓存攻击', '其他硬件漏洞'],
      datasets: [
        { label: '漏洞数量', data: [10, 8, 1, 1], backgroundColor: ['#283593', '#5c6bc0', '#ff4081', '#ffc107'] },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: { display: true, text: '基于20个CVE漏洞的类型分析' }},
    },
  });

  await Promise.all([
    fetchAndMergeCveData(),
    createTrendChart()
  ]);
});

</script>


