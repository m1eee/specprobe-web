<template>
  <section class="container mt-5">
    <button class="btn btn-outline-primary mb-3" @click="exportPdf">
      <i class="fas fa-file-pdf me-1" /> 导出当前页面
    </button>
    <div class="row g-4">
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

      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <i class="fas fa-chart-area me-2"></i>
            <span>机器风险分布趋势</span>
          </div>
          <div class="card-body p-0 chart-container">
            <canvas ref="riskTrendChartRef" />
          </div>
        </div>
      </div>
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

      <div class="col-12">
        <div class="card">
          <div
            class="card-header d-flex align-items-center justify-content-between"
          >
            <div class="d-flex align-items-center">
              <i class="fas fa-shield-alt me-2" />
              <span>CVE防护情况汇总表</span>
              <small class="ms-3 text-light opacity-75">
                基于已提交的 {{ stats.total_machines }} 台机器检测数据
              </small>
            </div>
            <div class="d-flex gap-3">
              <div class="d-flex align-items-center">
                <span class="badge bg-success me-2">●</span>
                <small>已防护</small>
              </div>
              <div class="d-flex align-items-center">
                <span class="badge bg-danger me-2">●</span>
                <small>未防护</small>
              </div>
            </div>
          </div>
          <div class="card-body">
            <div
              v-if="showInfo && stats.total_machines > 0"
              class="alert alert-info alert-dismissible fade show mb-4"
              role="alert"
            >
              <i class="fas fa-info-circle me-2"></i>
              <strong>数据说明：</strong>下表显示了基于您提交的
              <strong>{{ stats.total_machines }}</strong> 台机器检测报告生成的 CVE 防护状态汇总。
              每当您上传新的检测报告，此表会自动更新以包含新机器的防护状态。
              <button
                type="button"
                class="btn-close"
                aria-label="Close"
                @click="showInfo = false"
              ></button>
            </div>
          
            <div v-if="machines.length" class="row mb-4">
              <div class="d-flex align-items-center flex-wrap mb-3">
                <div class="me-2">
                  <h6 class="text-muted mb-0">
                    <i class="fas fa-server me-2"></i>已检测机器概览
                  </h6>
                </div>
                  <div class="card-body">
                      <div class="d-flex align-items-center gap-3 flex-wrap mb-3">
                          <div class="d-flex align-items-center gap-2">
                              <span class="text-muted small">排序：</span>
                              <select v-model="sortKey" class="form-select form-select-sm" style="width: 120px;">
                                  <option value="mac">MAC</option>
                                  <option value="os">OS</option>
                                  <option value="cpu">CPU</option>
                                  <option value="kernel">Kernel</option>
                                  <option value="time">Time</option>
                              </select>
                              <button type="button" class="btn btn-sm btn-outline-secondary" @click="toggleSortOrder">
                                  <i :class="sortOrder === 'asc' ? 'fas fa-arrow-up' : 'fas fa-arrow-down'"></i>
                                  {{ sortOrder === 'asc' ? '正序' : '逆序' }}
                              </button>
                          </div>

                          <div class="d-flex align-items-center gap-2">
                              <span class="text-muted small">CPU筛选：</span>
                              <select v-model="cpuFilter" class="form-select form-select-sm" style="width: 160px;">
                                  <option value="all">所有CPU</option>
                                  <optgroup label="Intel">
                                    <option value="intel-14">Intel 14代</option>
                                    <option value="intel-13">Intel 13代</option>
                                    <option value="intel-12">Intel 12代</option>
                                    <option value="intel-11">Intel 11代</option>
                                    <option value="intel-10">Intel 10代</option>
                                    <option value="intel-9">Intel 9代</option>
                                    <option value="intel-8">Intel 8代</option>
                                  </optgroup>
                                  <optgroup label="AMD">
                                    <option value="amd-7">AMD Ryzen 7000</option>
                                    <option value="amd-6">AMD Ryzen 6000</option>
                                    <option value="amd-5">AMD Ryzen 5000</option>
                                  </optgroup>
                                  <option value="other">其他</option>
                              </select>
                          </div>
                          <div class="d-flex align-items-center gap-2">
                              <span class="text-muted small">OS筛选：</span>
                              <select v-model="osFilter" class="form-select form-select-sm" style="width: 140px;">
                                  <option value="all">所有</option>
                                  <option value="ubuntu-22.04">Ubuntu 22.04</option>
                                  <option value="ubuntu-20.04">Ubuntu 20.04</option>
                                  <option value="ubuntu-18.04">Ubuntu 18.04</option>
                                  <option value="ubuntu-24.04">Ubuntu 24.04</option>
                                  <option value="ubuntu-16.04">Ubuntu 16.04</option>
                                  <option value="centos">CentOS</option>
                                  <option value="other">其他</option>
                              </select>
                          </div>
                          <div class="d-flex align-items-center gap-2">
                              <span class="text-muted small">Kernel筛选：</span>
                              <select v-model="kernelFilter" class="form-select form-select-sm" style="width: 140px;">
                                  <option value="all">所有</option>
                                  <option value="lt4">&lt; 4.0</option>
                                  <option value="4">4.0 - 4.19</option>
                                  <option value="5low">5.0 - 5.9</option>
                                  <option value="5high">5.10 - 5.19</option>
                                  <option value="ge6">&gt;= 6.0</option>
                                  <option value="other">其他</option>
                              </select>
                          </div>
                      </div>
                        <div class="position-relative">
                            <i class="fas fa-search position-absolute" 
                              style="left: 12px; top: 50%; transform: translateY(-50%); color: #6c757d;"></i>
                            <input v-model.trim="query" type="text" class="form-control ps-5"
                                  placeholder="按 MAC / OS / CPU / Kernel / Time 关键字搜索" />
                        </div>
                  </div>
                </div>
              <div
                v-for="machine in pagedReports"
                :key="machine.id"
                class="col-md-4 col-lg-2 mb-3"
              >
                <div
                  class="card border-0 bg-light h-100 machine-card"
                  role="button"
                  tabindex="0"
                  @click="openDetail(macOf(machine))"
                  @keydown.enter.prevent="openDetail(macOf(machine))"
                  @keydown.space.prevent="openDetail(macOf(machine))"
                >
                  <div class="card-body p-3">
                    <div class="d-flex align-items-center mb-2">
                      <i class="fas fa-desktop text-primary me-2" />
                      <h6 class="card-title mb-0 small">{{ machine.name }}</h6>
                    </div>
                    <div class="small text-muted">
                      <div class="mb-1">
                        <i class="fab fa-linux me-1" />{{ machine.os }}
                      </div>
                      <div class="mb-1 text-truncate" :title="machine.cpu">
                        <i class="fas fa-microchip me-1" />{{ machine.cpu }}
                      </div>
                      <div class="mb-1">
                        <i class="fas fa-code-branch me-1" />{{ machine.kernel }}
                      </div>
                      <div class="mb-1">
                        <i class="fas fa-clock me-1" />
                        {{ machine.report_time.split(' ')[0] }}
                      </div>
                      <div class="d-flex justify-content-between">
                        <span class="badge bg-primary small">{{ machine.vuln_count }}CVE</span>
                        <span
                          :class="[
                            'badge small',
                            machine.risk_count > 0 ? 'bg-warning' : 'bg-success']
                          "
                          >{{ machine.risk_count > 0 ? machine.risk_count + '风险' : '安全' }}</span
                        >
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <nav class="d-flex flex-wrap justify-content-between align-items-center mt-3">
              <div class="text-muted small mb-2 mb-md-0">
                共 {{ sortedReports.length }} 台，页 {{ page }} / {{ totalPages }}
              </div>

              <div class="d-flex align-items-center gap-2">
                <ul class="pagination pagination-sm mb-0">
                  <li class="page-item" :class="{ disabled: page === 1 }">
                    <a class="page-link" href="javascript:void(0)" @click="page > 1 && (page = page - 1)">上一页</a>
                  </li>

                  <li v-for="p in pagesToShow" :key="p"
                      class="page-item" :class="{ active: p === page }">
                    <a class="page-link" href="javascript:void(0)" @click="page = p">{{ p }}</a>
                  </li>

                  <li class="page-item" :class="{ disabled: page === totalPages }">
                    <a class="page-link" href="javascript:void(0)" @click="page < totalPages && (page = page + 1)">下一页</a>
                  </li>
                </ul>

                <select v-model.number="pageSize" class="form-select form-select-sm w-auto">
                  <option :value="6">每页 6</option>
                  <option :value="12">每页 12</option>
                  <option :value="24">每页 24</option>
                </select>
              </div>
            </nav>
            <div v-if="machines.length" class="row mt-4">
              <div class="col-md-3">
                <div class="card text-center border-primary">
                  <div class="card-body">
                    <h5 class="card-title text-primary">20</h5>
                    <p class="card-text small text-muted">检测的CVE数量</p>
                  </div>
                </div>
              </div>
              <div class="col-md-3">
                <div class="card text-center border-success">
                  <div class="card-body">
                    <h5 class="card-title text-success">{{ dynamicStats.fully_protected }}</h5>
                    <p class="card-text small text-muted">完全防护的CVE</p>
                  </div>
                </div>
              </div>
              <div class="col-md-3">
                <div class="card text-center border-warning">
                  <div class="card-body">
                    <h5 class="card-title text-warning">{{ dynamicStats.partially_protected }}</h5>
                    <p class="card-text small text-muted">部分防护的CVE</p>
                  </div>
                </div>
              </div>
              <div class="col-md-3">
                <div class="card text-center border-danger">
                  <div class="card-body">
                    <h5 class="card-title text-danger">{{ dynamicStats.unprotected }}</h5>
                    <p class="card-text small text-muted">未防护的CVE</p>
                  </div>
                </div>
              </div>
            </div>

            <div v-if="machines.length" class="mt-4">
              <div class="card border-info">
                <div class="card-body">
                  <h6 class="card-title text-info">
                    <i class="fas fa-lightbulb me-2" />操作建议
                  </h6>
                  <ul class="list-unstyled mb-0">
                    <li class="mb-2">
                      <i class="fas fa-upload text-primary me-2" />上传更多机器的检测报告以获得更全面的防护状态分析
                    </li>
                    <li class="mb-2">
                      <i class="fas fa-exclamation-triangle text-warning me-2" />重点关注防护率低于80%的CVE漏洞，及时应用安全补丁
                    </li>
                    <li>
                      <i class="fas fa-sync text-info me-2" />定期重新检测以确保防护措施的有效性
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
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
    <div v-if="showDetail" class="modal-mask" @click.self="showDetail=false">
      <div class="dialog">
        <header class="dialog-header">
          <h3>漏洞详情 - MAC:{{ selectedMac }}</h3>
          <button class="close" @click="showDetail=false">×</button>
        </header>

        <section class="dialog-body">
          <div v-if="loading">加载中...</div>
          <div v-else-if="errorMsg" class="error">{{ errorMsg }}</div>
          <table v-else class="cve-table">
            <thead>
              <tr>
                <th>CVE</th>
                <th>详情</th>
                <th>风险</th>
                <th>风险报告</th>
                <th>缓解措施</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in cves" :key="row.cve">
                <td>{{ row.cve }}</td>
                <td>{{ nameOf(row.cve) }}</td>
                <td>
                  <span v-if="row.affected" class="badge bg-danger">受影响</span>
                  <span v-else class="badge bg-success">安全</span>
                </td>
                <td style="white-space: pre-wrap;">{{ row.info }}</td>
                <td>
                  <div v-if="row.affected" class="mitigation-container">
                    <p 
                      v-for="(line, index) in getMitigationLines(CVE_Protection[row.cve])" 
                      :key="index" 
                      class="mitigation-line"
                    >
                      {{ line }}
                    </p>
                  </div>
                </td>
                </tr>
            </tbody>
          </table>
        </section>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref, computed, watch, watchEffect, onMounted } from 'vue'
import { Chart, registerables } from 'chart.js';
import axios from 'axios';
Chart.register(...registerables);

// --- Refs ---
const typeChartRef = ref(null);
const trendChartRef = ref(null);
const search = ref('');

const cveStaticDetails = [
  { cve: "CVE-2017-5753", type:"投机执行攻击",name: "Spectre V1", cvss: 5.6 ,detail: 'Spectre变体1 (边界检查绕过)'},
  { cve: "CVE-2017-5715", type:"投机执行攻击",name: "Spectre V2", cvss: 5.9 ,detail: 'Spectre变体2 (分支目标注入)'},
  { cve: "CVE-2017-5754", type:"投机执行攻击",name: "Meltdown", cvss: 5.6 ,detail: 'Meltdown (恶意数据缓存加载)'},
  { cve: "CVE-2018-3639", type:"投机执行攻击",name: "Spectre V4", cvss: 5.6 ,detail: '变体4 (推测存储绕过)'},
  { cve: "CVE-2018-3640", type:"投机执行攻击",name: "Spectre V3A", cvss: 4.3 ,detail: '变体3A (恶意系统寄存器读取)'},
  { cve: "CVE-2018-3615", type:"乱序执行攻击",name: "L1TF SGX", cvss: 5.6 ,detail: 'L1TF SGX (L1终端故障 - SGX)'},
  { cve: "CVE-2018-3620", type:"乱序执行攻击",name: "L1TF OS", cvss: 5.6 ,detail: 'L1TF OS (L1终端故障 - 操作系统)'},
  { cve: "CVE-2018-3646", type:"乱序执行攻击",name: "L1TF VMM", cvss: 5.6 ,detail: 'L1TF VMM (L1终端故障 - 虚拟机监视器)'},
  { cve: "CVE-2018-12126",type:"乱序执行攻击", name: "MSBDS", cvss: 6.5 ,detail: 'MSBDS (微架构存储缓冲区数据采样)'},
  { cve: "CVE-2018-12130", type:"乱序执行攻击",name: "MFBDS", cvss: 6.5 ,detail: 'MFBDS (微架构填充缓冲区数据采样)'},
  { cve: "CVE-2018-12127", type:"乱序执行攻击",name: "MLPDS", cvss: 6.5 ,detail: 'MLPDS (微架构加载端口数据采样)'},
  { cve: "CVE-2019-11091", type:"乱序执行攻击",name: "MDSUM", cvss: 3.8 ,detail: 'MDSUM (微架构数据采样无缓存内存)'},
  { cve: "CVE-2019-11135", type:"投机执行攻击",name: "TAA", cvss: 6.5 ,detail: 'TAA (TSX异步中止)'},
  { cve: "CVE-2018-12207", type:"其他硬件漏洞",name: "ITLBMH", cvss: 6.5 ,detail: 'ITLBMH (指令TLB多级页表)'},
  { cve: "CVE-2020-0543", type:"投机执行攻击",name: "SRBDS", cvss: 6.5 ,detail: 'SRBDS (特殊寄存器缓冲区数据采样)'},
  { cve: "CVE-2023-20593", type:"投机执行攻击",name: "Zenbleed", cvss: 6.5 ,detail: 'Zenbleed (AMD Zen2架构漏洞)'},
  { cve: "CVE-2022-40982", type:"数据预取侧信道攻击",name: "Downfall", cvss: 6.5 ,detail: 'Downfall (收集数据采样)'},
  { cve: "CVE-2022-4543", type:"数据预取侧信道攻击",name: "Entrybleed", cvss: 7.0 ,detail: 'EntryBleed (KASLR绕过)'},
  { cve: "CVE-2023-20569", type:"投机执行攻击",name: "Inception", cvss: 4.7 ,detail: 'Inception (AMD推测执行漏洞)'},
  { cve: "CVE-2023-23583", type:"其他硬件漏洞",name: "Reptar", cvss: 8.8 ,detail: 'Reptar (Intel序列化指令漏洞)'}
];

// 将动态计算的CVE数据替换掉旧的静态cveData
const dynamicCveData = computed(() => {
  const filtered = filteredReports.value;
  if (filtered.length === 0) return [];

  const staticInfoMap = new Map(cveStaticDetails.map(item => [item.cve, { ...item }]));

  const mergedData = cveStaticDetails.map(staticCve => {
    let affectedCount = 0;
    for (const machine of filtered) {
      const cveStatus = machine.cve_details?.find(c => c.cve === staticCve.cve);
      if (cveStatus?.affected) {
        affectedCount++;
      }
    }

    const totalMachines = filtered.length;
    const protectedCount = totalMachines - affectedCount;
    const protectionRate = totalMachines > 0 ? Math.round((protectedCount / totalMachines) * 100) : 100;

    return {
      cve: staticCve.cve,
      name: staticCve.name || 'N/A',
      type: staticCve.type || '未知类型',
      cvss: staticCve.cvss || 0,
      detail: staticCve.detail || 'No details available.',
      protected: protectedCount,
      total: totalMachines,
      protectionRate: protectionRate,
    };
  });

  return mergedData;
});

const filteredCveData = computed(() =>
  dynamicCveData.value.filter((v) => v.cve.toLowerCase().includes(search.value.toLowerCase()) || v.name.toLowerCase().includes(search.value.toLowerCase()))
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
  const cveList = dynamicCveData.value;
  if (!cveList.length) return 0;
  const total = cveList.reduce(
    (sum, item) => sum + item.protectionRate,
    0
  );
  return Math.round(total / cveList.length);
});
const riskRate = computed(() => 100 - avgProtectionRate.value);

const machines = ref([])
const riskTrendChartRef = ref(null);
const comparisonTable = ref([])

/* ----------- chart : 机器风险分布趋势 ---------- */
function createRiskTrendChart () {
  if (!machines.value.length) return;

  // 聚合到日维度，同时计算截止当日的累计值
  const daily = {};
  machines.value.forEach(m => {
    const date = m.report_time.split(' ')[0];
    if (!daily[date]) daily[date] = { total: 0, medium: 0, high: 0 };
    daily[date].total += 1;
    if (m.risk_count >= 5) daily[date].high += 1;
    else if (m.risk_count > 0) daily[date].medium += 1;
  });

  const sortedDates = Object.keys(daily).sort((a, b) => new Date(a) - new Date(b));
  const labels = sortedDates.map(d => {
    const dt = new Date(d);
    return `${dt.getUTCMonth() + 1}/${dt.getUTCDate()}`;
  });

  // 累积曲线
  let totalRunning = 0, mediumRunning = 0, highRunning = 0 , safeRunning = 0;
  const totalData  = [];
  const mediumData = [];
  const highData   = [];
  const safeData   = [];
  for (const d of sortedDates) {
    totalRunning  += daily[d].total;
    mediumRunning += daily[d].medium;
    highRunning   += daily[d].high;
    safeRunning   = (totalRunning - mediumRunning - highRunning);
    totalData.push(totalRunning);
    mediumData.push(mediumRunning);
    highData.push(highRunning);
    safeData.push(safeRunning);
  }

  new Chart(riskTrendChartRef.value.getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: '总机器数',
          data: totalData,
          borderColor: '#283593',
          backgroundColor: 'rgba(40,53,147,.15)',
          fill: true,
          tension: 0.3,
        },
        {
          label: '中度风险',
          data: mediumData,
          borderColor: '#ff9800',
          backgroundColor: 'rgba(255,152,0,.15)',
          fill: false,
          tension: 0.3,
        },
        {
          label: '高风险',
          data: highData,
          borderColor: '#dc3545',
          backgroundColor: 'rgba(220,53,69,.15)',
          fill: false,
          tension: 0.3,
        },
        {
          label: '低风险',
          data: safeData,
          borderColor: '#198754',
          backgroundColor: 'rgba(25,135,84,.15)',
          fill: false,
          tension: 0.3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom' },
        title: { display: true, text: '机器风险累积曲线' },
      },
      scales: {
        y: { beginAtZero: true }
      }
    },
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

// 机器概览
const reports = ref([])
const vulnerabilities = ref([])
const stats = ref({})
const showInfo = ref(true)   // 初始显示

// ==== 搜索关键字 ====
const query = ref('')
// ==== CPU筛选 ====
const cpuFilter = ref('all')
// ==== OS筛选 ====
const osFilter = ref('all')
// ==== Kernel筛选 ====
const kernelFilter = ref('all')
// ② 过滤后的数据（替换 v‑for 用这一份）
const filteredReports = computed(() => {
  let filtered = reports.value;

  if (query.value) {
    const q = query.value.toLowerCase()
    filtered = filtered.filter(r => {
      return [
        r.name,          // 设备名 / 主机名
        r.os,            // 操作系统
        r.cpu,           // CPU 型号
        r.kernel,        // 内核版本
        r.time           // 检测时间（最好格式化成字符串再比对）
      ]
        .filter(Boolean)               // 防空字段报错
        .some(v => String(v).toLowerCase().includes(q))
    })
  }

  if (cpuFilter.value !== 'all') {
    filtered = filtered.filter(r => getCpuGenerationCategory(r) === cpuFilter.value);
  }

  if (osFilter.value !== 'all') {
    filtered = filtered.filter(r => getOsCategory(r) === osFilter.value);
  }

  if (kernelFilter.value !== 'all') {
    filtered = filtered.filter(r => getKernelCategory(r) === kernelFilter.value);
  }

  return filtered
})

const getCpuGenerationCategory = (machine) => {
  const cpu = (machine.cpu || '').toLowerCase();

  // Intel: First, check for explicit "XXth gen" which is the most reliable.
  let match = cpu.match(/(\d{1,2})th gen/);
  if (match) {
    return `intel-${match[1]}`;
  }

  // Intel: If not found, check for the Core iX-YYYY... format.
  // This regex is improved to correctly handle "(tm)" and other variations.
  match = cpu.match(/core(?:\(r\))?(?:\(tm\))?\s*i\d[ -]?(\d{1,2})\d{3}/);
  if (match) {
    return `intel-${match[1]}`;
  }
  
  // AMD: Check for Ryzen X YYYY format.
  match = cpu.match(/ryzen(?:.tm)? \d[ -](\d)\d{3}/);
  if (match) {
    return `amd-${match[1]}`;
  }

  return 'other';
}

const getOsCategory = (machine) => {
  const os = (machine.os || '').toLowerCase();
  if (os.includes('centos')) return 'centos';
  if (os.includes('ubuntu')) {
    if (os.includes('22.04')) return 'ubuntu-22.04';
    if (os.includes('20.04')) return 'ubuntu-20.04';
    if (os.includes('18.04')) return 'ubuntu-18.04';
    if (os.includes('24.04')) return 'ubuntu-24.04';
    if (os.includes('16.04')) return 'ubuntu-16.04';
  }
  return 'other';
}

const getKernelCategory = (machine) => {
  const kernel = (machine.kernel || '').toLowerCase();
  const match = kernel.match(/^(\d+)\.(\d+)/);
  if (!match) return 'other';
  const major = parseInt(match[1]);
  const minor = parseInt(match[2]);
  if (major < 4) return 'lt4';
  if (major === 4 && minor <= 19) return '4';
  if (major === 5 && minor >= 0 && minor <= 9) return '5low';
  if (major === 5 && minor >= 10 && minor <= 19) return '5high';
  if (major >= 6) return 'ge6';
  return 'other';
}

// ==== 排序相关 ====
const sortKey = ref('time')   
const sortOrder = ref('asc')  

/**  @type {{[k: string]: (m:any) => string}} */
const SORT_GETTERS = {
  mac:    (m) => m.mac || m.mac_address || m.MAC || '',
  os:     (m) => m.os || '',
  cpu:    (m) => m.cpu || '',
  kernel: (m) => m.kernel || '',
  time:   (m) => m.report_time || m.time || ''
}

function toggleSortOrder () {
  sortOrder.value = sortOrder.value === 'asc' ? 'desc' : 'asc'
}

const sortedReports = computed(() => {
  const getter = SORT_GETTERS[sortKey.value] || SORT_GETTERS.time
  const arr = filteredReports.value.slice()

  arr.sort((a, b) => {
    const av = String(getter(a) ?? '').toLowerCase()
    const bv = String(getter(b) ?? '').toLowerCase()
    const cmp = av.localeCompare(bv, 'zh')
    return sortOrder.value === 'asc' ? cmp : -cmp
  })

  return arr
})


async function fetchData() {
  try {
    const res = await axios.get('/api/reports/')
    const baseMachines = res.data.machines || [];
    stats.value = res.data.stats; // Keep original global stats for display
    machines.value = baseMachines; // For charts that use all machines

    // Fetch detailed CVE status for each machine and attach it.
    // This can be slow if there are many machines.
    const detailedMachines = await Promise.all(baseMachines.map(async (machine) => {
      const mac = macOf(machine);
      try {
        const { data } = await axios.get(`/api/device-vuln/${encodeURIComponent(mac)}/`);
        return { ...machine, cve_details: data.cves || [] };
      } catch (e) {
        console.error(`Failed to fetch details for MAC ${mac}:`, e);
        return { ...machine, cve_details: [] }; // Return machine with empty details on error
      }
    }));
    
    reports.value = detailedMachines;

  } catch (e) {
    console.error("Failed to fetch initial report data:", e);
  }
}

function getMitigationLines(text) {
  if (!text) return [];
  // 按换行符分割，并过滤掉可能存在的空行
  return text.split('\n').filter(line => line.trim() !== '');
}
// New computed property to calculate stats based on filtered data
const dynamicStats = computed(() => {
  const cveList = dynamicCveData.value;
  const stats = {
    fully_protected: 0,
    partially_protected: 0,
    unprotected: 0,
  };

  if (filteredReports.value.length === 0) {
    return stats; // Return zeroed stats if no machines are in the filter
  }

  for (const cve of cveList) {
    if (cve.protectionRate === 100) {
      stats.fully_protected++;
    } else if (cve.protectionRate === 0) {
      stats.unprotected++;
    } else {
      stats.partially_protected++;
    }
  }
  return stats;
});

// ===== 分页状态 =====
const page = ref(1)            // 当前页
const pageSize = ref(6)       // 每页条数（建议 6/12/24 等）

// 总页数
const totalPages = computed(() => {
  const total = sortedReports.value.length
  return Math.max(1, Math.ceil(total / pageSize.value))
})

// 当前页要显示的数据（基于 sortedReports 再分页）
const pagedReports = computed(() => {
  const start = (page.value - 1) * pageSize.value
  const end = start + pageSize.value
  return sortedReports.value.slice(start, end)
})

// 页码列表（最多展示 5 个页码，当前页在中间）
const pagesToShow = computed(() => {
  const t = totalPages.value
  const cur = page.value
  const win = 5
  let start = Math.max(1, cur - Math.floor(win / 2))
  let end = Math.min(t, start + win - 1)
  start = Math.max(1, end - win + 1)
  return Array.from({ length: end - start + 1 }, (_, i) => start + i)
})

// ===== 当搜索或排序变化时，自动回到第 1 页 =====
watch([() => query.value, () => sortKey.value, () => sortOrder.value, () => cpuFilter.value, () => osFilter.value, () => kernelFilter.value], () => {
  page.value = 1
})

// 每页条数变化时，回到第 1 页
watch(pageSize, () => {
  page.value = 1
})

// 防止当前页超过总页数（例如过滤后数据变少）
watchEffect(() => {
  if (page.value > totalPages.value) page.value = totalPages.value
})

// ===== CVE 详情 =====
const showDetail = ref(false)
const loading = ref(false)
const errorMsg = ref('')
const selectedMac = ref('')
const cves = ref([]) // [{ cve, affected, info }, ...]
const CVE_NAME = {
  "CVE-2017-5753":"Spectre变体1 (边界检查绕过)",
  "CVE-2017-5715":"Spectre变体2 (分支目标注入)",
  "CVE-2017-5754":"Meltdown (恶意数据缓存加载)",
  "CVE-2018-3640":"变体3A (恶意系统寄存器读取)",
  "CVE-2018-3639":"变体4 (推测存储绕过)",
  "CVE-2018-3615":"L1TF SGX (L1终端故障 - SGX)",
  "CVE-2018-3620":"L1TF OS (L1终端故障 - 操作系统)",
  "CVE-2018-3646":"L1TF VMM (L1终端故障 - 虚拟机监视器)",
  "CVE-2018-12126":"MSBDS (微架构存储缓冲区数据采样)",
  "CVE-2018-12130":"MFBDS (微架构填充缓冲区数据采样)",
  "CVE-2018-12127":"MLPDS (微架构加载端口数据采样)",
  "CVE-2019-11091":"MDSUM (微架构数据采样无缓存内存)",
  "CVE-2019-11135":"TAA (TSX异步中止)",
  "CVE-2018-12207":"ITLBMH (指令TLB多级页表)",
  "CVE-2020-0543":"SRBDS (特殊寄存器缓冲区数据采样)",
  "CVE-2023-20593":"Zenbleed (AMD Zen2架构漏洞)",
  "CVE-2022-40982":"Downfall (收集数据采样)",
  "CVE-2023-20569":"Inception (AMD推测执行漏洞)",
  "CVE-2023-23583":"Reptar (Intel序列化指令漏洞)",
  "CVE-2022-4543":"EntryBleed (KASLR绕过)",
}
const CVE_Protection = {
"CVE-2017-5753": "固件/微码：常规更新即可；主要缓解在软件侧完成。\n操作系统/内核：使用包含 V1 缓解的内核（默认启用），不要设置 `nospectre_v1`。关闭非特权 eBPF（减少内核 Gadget 暴露）：`sysctl kernel.unprivileged_bpf_disabled=1`；许多发行版已默认关闭\n应用/编译器：对可疑越界索引点做投机安全化：在内核/低层代码使用 `array_index_nospec()` / `barrier_nospec` 等原语，或等价的掩码/栅栏序列；用户态可用等价技巧或编译器内建。\n验证与观测：`cat /sys/devices/system/cpu/vulnerabilities/spectre_v1`；检查是否显示诸如 `usercopy/swapgs barriers` 与 `__user pointer sanitization`",
"CVE-2017-5715": "固件/微码：更新以支持IBRS/IBPB/STIBP/eIBRS等硬件能力。\n操作系统/内核：让内核自动选择最优缓解：`spectre_v2=auto`（默认）；不要关闭。\n对不具 eIBRS 的老平台，确保启用 retpoline（编译器+内核支持），并按需启用 IBPB/STIBP 与 RSB stuffing。\n对多线程(SMT) 机器，按负载与风险平衡开启 STIBP；对跨超线程攻击更敏感的场景可考虑 `nosmt`。\n应用/编译器：内核模块与关键用户态组件（JIT、插件）应使用带 retpoline 支持的编译器重建。\n虚拟化/云：来宾与宿主都应有 IBPB/RSB 填充等机制；对不具 eIBRS 的平台谨慎混布租户/工作负载。\n验证与观测：`cat /sys/devices/system/cpu/vulnerabilities/spectre_v2`",
"CVE-2017-5754": "固件/微码：跟进厂商微码；部分新代处理器已在硬件侧免疫。\n操作系统/内核：启用 KPTI（又称 KAISER）：`pti=on`（多数发行版默认开）。\n虚拟化/云：容器/来宾安全依赖宿主内核是否启用 KPTI。\n验证与观测：`cat /sys/devices/system/cpu/vulnerabilities/meltdown`",
"CVE-2018-3640": "固件/微码：更新微码，对 RDRAND / RDSEED / SGX 等“特殊寄存器读取”路径加以序列化/隔离。\n操作系统/内核：一般无需额外操作，保持内核新版本即可。Windows 亦通过更新交付相关微码。\n验证：关注平台微码/BIOS发行说明或 `dmesg | grep microcode`",
"CVE-2018-3639": "固件/微码：需微码支持 SSBD。\n操作系统/内核：Linux 默认按需缓解；可强制：`spec_store_bypass_disable=on`；用户态可通过 prctl/seccomp 按进程粒度禁用 SSB。\n不要用 `spec_store_bypass_disable=off`（会暴露风险）。\n验证：`cat /sys/devices/system/cpu/vulnerabilities/spec_store_bypass`",
"CVE-2018-3615": "固件/微码：更新微码；对 SGX 用户可视需求禁用 SGX。\n操作系统/内核：内核永久启用 PTE 反转抵御本机用户态攻击。虚拟化场景建议：\n启用 L1D cache flush on VMENTER（KVM：`kvm-intel.vmentry_l1d_flush=cond/always`）。\n不可信来宾 + 需要强防护：`l1tf=full,force`；并强烈建议 `nosmt`。\n或者禁用 EPT（性能损耗较大）。\n验证：`cat /sys/devices/system/cpu/vulnerabilities/l1tf` 可见 PTE inversion / L1D flush / SMT 状态。",
"CVE-2018-3620": "固件/微码：更新微码；对 SGX 用户可视需求禁用 SGX。\n操作系统/内核：内核永久启用 PTE 反转抵御本机用户态攻击。虚拟化场景建议：\n启用 L1D cache flush on VMENTER（KVM：`kvm-intel.vmentry_l1d_flush=cond/always`）。\n不可信来宾 + 需要强防护：`l1tf=full,force`；并强烈建议 `nosmt`。\n或者禁用 EPT（性能损耗较大）。\n验证：`cat /sys/devices/system/cpu/vulnerabilities/l1tf` 可见 PTE inversion / L1D flush / SMT 状态。",
"CVE-2018-3646": "固件/微码：更新微码；对 SGX 用户可视需求禁用 SGX。\n操作系统/内核：内核永久启用 PTE 反转抵御本机用户态攻击。虚拟化场景建议：\n启用 L1D cache flush on VMENTER（KVM：`kvm-intel.vmentry_l1d_flush=cond/always`）。\n不可信来宾 + 需要强防护：`l1tf=full,force`；并强烈建议 `nosmt`。\n或者禁用 EPT（性能损耗较大）。\n验证：`cat /sys/devices/system/cpu/vulnerabilities/l1tf` 可见 PTE inversion / L1D flush / SMT 状态。",
"CVE-2018-12126": "固件/微码：更新以获得 VERW 缓冲清理与相关标志。\n操作系统/内核：默认启用缓解；可用 `mds=full` 或 完全缓解 `mds=full,nosmt`（对多数受影响 CPU，关闭 SMT 才能完全缓解）。\n来宾切换与返回用户态时清理 CPU 缓冲。\n验证：`cat /sys/devices/system/cpu/vulnerabilities/mds`。",
"CVE-2019-11135": "固件/微码：更新微码以支持 TSX 控制寄存器与缓解序列。\n操作系统/内核：\n选项：`tsx_async_abort=full`（或带 `,nosmt`）；也可直接 `tsx=off` 彻底禁用 TSX。\n与 MDS 共用缓解机制，禁掉 MDS 的同时别忘了处理 TAA。\n验证：`/sys/devices/system/cpu/vulnerabilities/tsx_async_abort`。",
"CVE-2018-12207": "虚拟化/云（重点）：在 KVM 上启用NX 大页分裂缓解：\nRHEL 等参数：`kvm.nx_huge_pages=auto/force`（必要时 `force`）；或在老版本使用 `kvm.no_huge_pages=1`。\n也可在来宾上避免可执行的大页。\n微码中 `IA32_ARCH_CAPABILITIES[PSCHANGE_MC_NO]` 可表明免疫。\n运行态/启动项与 sysfs 均可切换与查看。\n验证：`/sys/devices/system/cpu/vulnerabilities/itlb_multihit`。",
"CVE-2020-0543": "固件/微码：必须更新；微码对 RDRAND/RDSEED/SGX EGETKEY 做序列化与跨核隔离，默认启用。\n操作系统/内核：Linux 自带 SRBDS 缓解（可通过 `srbds=` 控制，默认开启）。\n验证：`/sys/devices/system/cpu/vulnerabilities/srbds`。",
"CVE-2023-20593": "固件/微码：升级到 AMD 公布的修复微码/BIOS（AGESA）。这是首选与根本措施。\n操作系统/内核：在微码未到位前，可采用内核/固件的临时绕过位（设置特定 MSR 的“chicken bit”以关闭存在风险的向量寄存器重命名路径；主流发行版已集成内核侧临时缓解，随后被微码替换）。Ubuntu 等已发布对策与指导。\n验证：检查微码版本（`cat /proc/cpuinfo` / 厂商发布说明）与发行版公告。",
"CVE-2022-40982": "固件/微码：更新以获得 GDS_CTRL 与相关锁定位，默认启用缓解。\n操作系统/内核：\nLinux 默认开启；可通过 `gather_data_sampling=force` 在无微码时退化为禁用 AVX 的软件缓解（会影响使用 AVX 的负载）。\n切勿在多租户/云环境关闭（`gather_data_sampling=off`）。\n虚拟化环境需确保来宾不可关闭该缓解。\n验证：`/sys/devices/system/cpu/vulnerabilities/gather_data_sampling`。",
"CVE-2023-20569": "固件/微码：升级到 AMD 公布的微码（Zen1–Zen4 受影响，Zen5 不受影响）；AMD 后续通报重申 SB‑7005 的缓解仍有效。\n操作系统/内核：\nLinux 提供 SRSO 缓解与 sysfs 状态；保持最新内核与微码。必要时 `srso=` 开关可调整策略。\n结合 IBPB / RSB 填充 / STIBP（SMT） 等机制降低跨上下文泄漏。\n验证：`/sys/devices/system/cpu/vulnerabilities/spec_rstack_overflow`。",
"CVE-2023-23583": "固件/微码：务必更新至 Intel 发布的 2023‑11 微码（OEM BIOS/固件或 OS 微码包），以修复指令前缀解析异常引发的本地提权/信息泄露/DoS 风险。\n操作系统/内核：保持最新稳定内核；云/虚拟化平台同步宿主与来宾微码。\n验证：参考硬件厂商通报或发行版微码包公告。",
"CVE-2022-4543": "现状小结：研究表明攻击可在启用 KPTI 的 Linux 上泄露入口代码布局，从而绕过内核地址空间布局随机化（KASLR）。论文建议的核心防御是函数粒度/入口路径的启动期重定位（FG‑KASLR 类方案），以增加入口地址不确定性；实现上会带来一定启动开销。\n实操建议：\n升级到包含该问题修复/缓解的内核（跟踪你所用发行版的安全修复与是否采用更细粒度 KASLR 方案）。\n不要把 KASLR 当成唯一防线：结合 KPTI、内核 Lockdown、仅签名模块、禁用非特权 eBPF、最小化攻击面（裁剪不必要 syscalls/模块）、启用 SELinux/AppArmor 等综合加固。\n对需要“入口地址难测性”的高敏场景，评估启用/迁移到具备函数粒度 KASLR的内核/补丁集。",
}
const nameOf = (cve) => CVE_NAME[cve] || ''
async function openDetail(mac) {
  showDetail.value = true
  loading.value = true
  errorMsg.value = ''
  selectedMac.value = mac
  try {
    const { data } = await axios.get(`/api/device-vuln/${encodeURIComponent(mac)}/`)
    cves.value = data.cves || []
    console.log('open detail', cves.value)
  } catch (e) {
    errorMsg.value = e?.response?.data?.detail || e.message || '加载失败'
  } finally {
    loading.value = false
  }
}
// ====== 历史检测报告：搜索 / 排序 / 分页 ======
const historyQuery = ref('')
const historySortKey = ref('report_time')  // 默认按时间
const historySortOrder = ref('desc')       // 默认逆序（最新在前）

const HISTORY_SORT_GETTERS = {
  id:           (r) => Number(r.id ?? 0),
  mac:          (r) => r.mac || '',
  cpu:          (r) => r.cpu || '',
  architecture: (r) => r.architecture || '',
  kernel:       (r) => r.kernel || '',
  vuln_count:   (r) => Number(r.vuln_count ?? 0),
  risk_count:   (r) => Number(r.risk_count ?? 0),
  report_time:  (r) => r.report_time || r.time || ''  // 接口里哪个有就用哪个
}

const historyFilteredReports = computed(() => {
  if (!historyQuery.value) return reports.value
  const q = historyQuery.value.toLowerCase()
  return reports.value.filter(r => {
    return [
      String(r.id ?? '').toLowerCase(),
      (r.mac || '').toLowerCase(),
      (r.cpu || '').toLowerCase(),
      (r.architecture || '').toLowerCase(),
      (r.kernel || '').toLowerCase(),
      String(r.report_time || r.time || '').toLowerCase()
    ].some(v => v.includes(q))
  })
})

const historySortedReports = computed(() => {
  const getter = HISTORY_SORT_GETTERS[historySortKey.value] || HISTORY_SORT_GETTERS.report_time
  const arr = historyFilteredReports.value.slice()

  const numericKeys = new Set(['id', 'vuln_count', 'risk_count'])
  arr.sort((a, b) => {
    const av = getter(a)
    const bv = getter(b)
    let cmp
    if (numericKeys.has(historySortKey.value)) {
      cmp = (av - bv) || 0
    } else {
      cmp = String(av).toLowerCase().localeCompare(String(bv).toLowerCase(), 'zh')
    }
    return historySortOrder.value === 'asc' ? cmp : -cmp
  })
  return arr
})

// 分页
const historyPage = ref(1)
const historyPageSize = ref(12)

const historyTotalPages = computed(() => {
  const total = historySortedReports.value.length
  return Math.max(1, Math.ceil(total / historyPageSize.value))
})

// 变化时回到第一页
watch([historyQuery, historySortKey, historySortOrder], () => {
  historyPage.value = 1
})
watch(historyPageSize, () => {
  historyPage.value = 1
})
watchEffect(() => {
  if (historyPage.value > historyTotalPages.value) {
    historyPage.value = historyTotalPages.value
  }
})


// 机器对象里 MAC 字段可能有不同命名，这里做个兜底
const macOf = (m) => m?.mac || m?.mac_address || m?.MAC || ''


const cpuVendorCanvas = ref(null)
const securityStatusCanvas = ref(null)
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

onMounted(async() => {
  await fetchData();

  new Chart(typeChartRef.value.getContext('2d'), {
    type: 'bar',
    data: {
      labels: ['投机执行攻击', '乱序执行攻击', '数据预取侧信道攻击', '其他硬件漏洞'],
      datasets: [
        { label: '漏洞数量', data: [9, 7, 2, 2], backgroundColor: ['#283593', '#5c6bc0', '#ff4081', '#ffc107'] },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: { display: true, text: '基于20个CVE漏洞的类型分析' }},
    },
  });
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
  createRiskTrendChart();
  
  await Promise.all([
    createTrendChart()
  ]);
});

</script>


<style scoped>
.machine-card { position: relative; z-index: 1; }
.modal-mask {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1050;
}

.dialog {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
  width: 85vw;  /* 调整为90%视口宽度，使弹窗更宽 */
  max-width: 1400px;  /* 设置最大宽度上限，避免过宽 */
  max-height: 80vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.dialog-header {
  padding: 1rem;
  border-bottom: 1px solid #dee2e6;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.dialog-header h3 {
  margin: 0;
}

.dialog-header .close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
}

.dialog-body {
  padding: 1rem;
  overflow-y: auto;
}

.cve-table {
  width: 100%;  /* 确保表格占据整个弹窗宽度 */
  border-collapse: collapse;
}

.cve-table th, .cve-table td {
  border: 1px solid #dee2e6;
  padding: 0.75rem;
  text-align: left;
  vertical-align: top;
}

.cve-table th {
  background-color: #f8f9fa;
  font-weight: bold;
}
/* --- 新增以下样式 --- */
.mitigation-container {
  max-height: 120px; /* 设定最大高度以触发滚动 */
  overflow-y: auto;  /* 垂直方向内容溢出时显示滚动条 */
  word-break: break-word;
  padding-right: 8px; /* 防止滚动条遮挡文字 */
}

.mitigation-line {
  margin-bottom: 0.5em; /* 设置行间距 */
  padding-left: 1.2em;  /* 为黑点留出空间，使文本向右缩进 */
  position: relative;  
  margin-left: 0;
  margin-block-start: 0;
  margin-block-end: 0.5em;
}

/* 使用 ::before 伪元素在每一行前面添加一个加粗的黑点 */
.mitigation-line::before {
  content: '•';
  font-weight: bold;
  position: absolute;
  left: 0;
  top: 0;
  color: #000;
}
</style>