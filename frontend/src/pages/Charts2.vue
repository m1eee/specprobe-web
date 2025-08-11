<template>
  <section class="container mt-5">
    <button class="btn btn-outline-primary mb-3" @click="exportPdf">
      <i class="fas fa-file-pdf me-1" /> 导出当前页面
    </button>
    <div class="row g-4">
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
      <div class="col-md-6">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-server me-2"></i>
            <span>内核版本漏洞累计</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="kernelChartRef" />
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-microchip me-2"></i>
            <span>CPU厂商平均漏洞</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="cpuAvgChartRef" />
          </div>
        </div>
      </div>
    </div>
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
                    :style="{ width: avgProtectionRate + '%' }"
                  />
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
                      <th>漏洞类型</th>
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
                      <td>{{ vuln.type }}</td>
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
  { cve: "CVE-2017-5753", type:"推测执行漏洞",name: "Spectre V1", cvss: 5.6 ,detail: 'Spectre变体1 (边界检查绕过)'},
  { cve: "CVE-2017-5715", type:"推测执行漏洞",name: "Spectre V2", cvss: 5.9 ,detail: 'Spectre变体2 (分支目标注入)'},
  { cve: "CVE-2017-5754", type:"推测执行漏洞",name: "Meltdown", cvss: 5.6 ,detail: 'Meltdown (恶意数据缓存加载)'},
  { cve: "CVE-2018-3639", type:"推测执行漏洞",name: "Spectre V4", cvss: 5.6 ,detail: '变体4 (推测存储绕过)'},
  { cve: "CVE-2018-3640", type:"推测执行漏洞",name: "Spectre V3A", cvss: 4.3 ,detail: '变体3A (恶意系统寄存器读取)'},
  { cve: "CVE-2018-3615", type:"推测执行漏洞",name: "L1TF SGX", cvss: 5.6 ,detail: 'L1TF SGX (L1终端故障 - SGX)'},
  { cve: "CVE-2018-3620", type:"推测执行漏洞",name: "L1TF OS", cvss: 5.6 ,detail: 'L1TF OS (L1终端故障 - 操作系统)'},
  { cve: "CVE-2018-3646", type:"推测执行漏洞",name: "L1TF VMM", cvss: 5.6 ,detail: 'L1TF VMM (L1终端故障 - 虚拟机监视器)'},
  { cve: "CVE-2018-12126",type:"侧信道漏洞", name: "MSBDS", cvss: 6.5 ,detail: 'MSBDS (微架构存储缓冲区数据采样)'},
  { cve: "CVE-2018-12130", type:"侧信道漏洞",name: "MFBDS", cvss: 6.5 ,detail: 'MFBDS (微架构填充缓冲区数据采样)'},
  { cve: "CVE-2018-12127", type:"侧信道漏洞",name: "MLPDS", cvss: 6.5 ,detail: 'MLPDS (微架构加载端口数据采样)'},
  { cve: "CVE-2019-11091", type:"侧信道漏洞",name: "MDSUM", cvss: 3.8 ,detail: 'MDSUM (微架构数据采样无缓存内存)'},
  { cve: "CVE-2019-11135", type:"侧信道漏洞",name: "TAA", cvss: 6.5 ,detail: 'TAA (TSX异步中止)'},
  { cve: "CVE-2018-12207", type:"内存漏洞",name: "ITLBMH", cvss: 6.5 ,detail: 'ITLBMH (指令TLB多级页表)'},
  { cve: "CVE-2020-0543", type:"侧信道漏洞",name: "SRBDS", cvss: 6.5 ,detail: 'SRBDS (特殊寄存器缓冲区数据采样)'},
  { cve: "CVE-2023-20593", type:"推测执行漏洞",name: "Zenbleed", cvss: 6.5 ,detail: 'Zenbleed (AMD Zen2架构漏洞)'},
  { cve: "CVE-2022-40982", type:"侧信道漏洞",name: "Downfall", cvss: 6.5 ,detail: 'Downfall (收集数据采样)'},
  { cve: "CVE-2022-4543", type:"侧信道漏洞",name: "Entrybleed", cvss: 7.0 ,detail: 'EntryBleed (KASLR绕过)'},
  { cve: "CVE-2023-20569", type:"推测执行漏洞",name: "Inception", cvss: 4.7 ,detail: 'Inception (AMD推测执行漏洞)'},
  { cve: "CVE-2023-23583", type:"其它漏洞",name: "Reptar", cvss: 8.8 ,detail: 'Reptar (Intel序列化指令漏洞)'}
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
    const staticInfoMap = new Map(cveStaticDetails.map(item => [item.cve, { name: item.name, type: item.type, cvss: item.cvss, detail: item.detail }]));
    const mergedData = fetchedVulnerabilities.map(vuln => {
      const staticInfo = staticInfoMap.get(vuln.cve) || {};
      const totalMachines = vuln.protected_count + vuln.affected_count + vuln.unknown_count;
      const protectionRate = totalMachines > 0 ? Math.round((vuln.protected_count / totalMachines) * 100) : 100;

      return {
        cve: vuln.cve,
        name: staticInfo.name || 'N/A',
        type: staticInfo.type || '未知类型',
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
    console.log('Fetched machines:', machines.value)
  } catch (e) {
    console.error(e)
  }
}

// 计算 CPU 厂商分布
const vendorCounts = computed(() => {
  const counts = { Intel: 0, AMD: 0, Other: 0 }
  machines.value.forEach(row => {
    const cpu = (row.cpu || '').toLowerCase()
    if (cpu.includes('intel')||cpu.includes('Intel')) counts.Intel++
    else if (cpu.includes('amd')||cpu.includes('AMD')) counts.AMD++
    else counts.Other++
  })
  console.log('Vendor counts:', counts)
  return counts        // {Intel: n, AMD: m, Other: k}
})
// 计算系统安全状态
const securityStatusCounts = computed(() => {
  const counts = { 'danger': 0, 'safe': 0 }
  machines.value.forEach(row => {
    const risk = row.risk_count
    if (risk > 0) counts['danger']++
    else counts['safe']++
  })
  return counts        // {Intel: n, AMD: m, Other: k}
})

/* ------------ chart : 内核版本漏洞累计 ----------- */
const kernelChartRef = ref(null);
function normalizeVersion(raw) {
  // 提取形如 5.11.0 的数字段落
  const match = raw.match(/[0-9]+(?:\.[0-9]+)*/);
  return match ? match[0] : raw;
}

function createKernelChart () {
  if (!machines.value.length) return;
  const kernelAgg = {}; // {version: {sum: x, count: y}}
  machines.value.forEach(m => {
    const versionKey = normalizeVersion((m.kernel || m.kernel_version || '未知').trim());
    const vulns = m.risk_count ?? 0; // 假设 risk_count 为机器漏洞数
    if (!kernelAgg[versionKey]) kernelAgg[versionKey] = { sum: 0, count: 0 };
    kernelAgg[versionKey].sum += vulns;
    kernelAgg[versionKey].count += 1;
  });
  const labels = Object.keys(kernelAgg);
  const data = labels.map(v => {
    const { sum, count } = kernelAgg[v];
    return count ? parseFloat((sum / count).toFixed(2)) : 0;
  });
  new Chart(kernelChartRef.value.getContext('2d'), {
    type: 'bar',
    data: { labels, datasets: [{ label: '平均漏洞数', data, backgroundColor: '#5c6bc0' }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: { display: true, text: '不同内核版本平均漏洞数' }
      },
      scales: {
        x: { title: { display: true, text: '内核版本' } },
        y: { beginAtZero: true, title: { display: true, text: '平均漏洞数' } }
      }
    }
  });
}

// --- 新增图表: CPU厂商平均漏洞数 ---
const cpuAvgChartRef = ref(null);
function createCpuAvgChart() {
  if (!machines.value.length) return;

  // 1. 初始化聚合对象
  const vendorAgg = {
    Intel: { totalVulns: 0, machineCount: 0 },
    AMD: { totalVulns: 0, machineCount: 0 },
    Other: { totalVulns: 0, machineCount: 0 },
  };

  // 2. 遍历机器数据并聚合
  machines.value.forEach(machine => {
    const cpu = (machine.cpu || '').toLowerCase();
    const riskCount = machine.risk_count ?? 0;
    
    if (cpu.includes('intel')) {
      vendorAgg.Intel.totalVulns += riskCount;
      vendorAgg.Intel.machineCount++;
    } else if (cpu.includes('amd')) {
      vendorAgg.AMD.totalVulns += riskCount;
      vendorAgg.AMD.machineCount++;
    } else {
      vendorAgg.Other.totalVulns += riskCount;
      vendorAgg.Other.machineCount++;
    }
  });

  // 3. 计算平均值
  const avgIntel = vendorAgg.Intel.machineCount > 0 ? parseFloat((vendorAgg.Intel.totalVulns / vendorAgg.Intel.machineCount).toFixed(2)) : 0;
  const avgAmd = vendorAgg.AMD.machineCount > 0 ? parseFloat((vendorAgg.AMD.totalVulns / vendorAgg.AMD.machineCount).toFixed(2)) : 0;
  const avgOther = vendorAgg.Other.machineCount > 0 ? parseFloat((vendorAgg.Other.totalVulns / vendorAgg.Other.machineCount).toFixed(2)) : 0;

  // 4. 创建图表
  new Chart(cpuAvgChartRef.value.getContext('2d'), {
    type: 'bar',
    data: {
      labels: ['Intel', 'AMD', '其他'],
      datasets: [{
        label: '平均风险漏洞数',
        data: [avgIntel, avgAmd, avgOther],
        backgroundColor: ['#0d6efd', '#dc3545', '#6c757d'],
        borderColor: ['#0d6efd', '#dc3545', '#6c757d'],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        },
        title: {
          display: true,
          text: '各CPU厂商的平均风险漏洞数'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: '平均漏洞数'
          }
        }
      }
    }
  });
}
// 导出 PDF 功能
import html2pdf from 'html2pdf.js'
function exportPdf () {
  const element = document.body                

  const { scrollWidth, scrollHeight } = element
  html2pdf().set({
    margin: 10,
    filename: 'dashboard.pdf',
    html2canvas: { scale: 4, useCORS: true },
    jsPDF: { unit: 'px', format: [scrollWidth + 20, scrollHeight + 20] } 
  })
    .from(element)
    .save()
}

onMounted(async() => {
  await fetchData();

  // 创建所有图表
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

  new Chart(securityStatusCanvas.value.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['存在风险', '相对安全'],
      datasets: [
        {
          data: [securityStatusCounts.value['danger'], securityStatusCounts.value['safe']],
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

  createKernelChart();
  createCpuAvgChart(); // <-- 调用新图表的创建函数
  
  await Promise.all([
    fetchAndMergeCveData(),
  ]);
});

</script>