<template>
  <section class="container mt-5">
    <!-- 历史检测报告 -->
    <div class="card mb-5">
      <div class="card-header d-flex align-items-center">
        <i class="fas fa-list me-2" />
        <span>历史检测报告</span>
      </div>
      <div class="card-body">
      <!-- 工具条：排序 + 顺序 + 搜索 -->
      <div class="d-flex align-items-center gap-2 flex-wrap mb-3">
        <span class="text-muted small me-2">排序：</span>

        <select v-model="historySortKey" class="form-select form-select-sm w-auto">
          <option value="id">报告ID</option>
          <option value="mac">MAC</option>
          <option value="cpu">CPU</option>
          <option value="architecture">架构</option>
          <option value="kernel">内核</option>
          <option value="vuln_count">漏洞总数</option>
          <option value="risk_count">风险漏洞</option>
          <option value="report_time">检测时间</option>
        </select>

        <button type="button"
                class="btn btn-sm btn-outline-secondary"
                @click="toggleHistorySortOrder">
          <i :class="historySortOrder === 'asc' ? 'fas fa-arrow-up' : 'fas fa-arrow-down'"></i>
          {{ historySortOrder === 'asc' ? '正序' : '逆序' }}
        </button>

        <!-- 搜索框-->
        <div class="ms-auto flex-grow-1" style="max-width: 600px;">
          <input v-model.trim="historyQuery"
                type="text"
                class="form-control"
                placeholder="按 ID / MAC / CPU / 架构 / 内核 / 时间 关键字搜索" />
        </div>
      </div>

        <div class="table-responsive">
          <table class="table table-hover">
            <thead>
              <tr>
                <th>报告ID</th>
                <th>MAC地址</th>
                <th>CPU型号</th>
                <th>处理器架构</th>
                <th>内核版本</th>
                <th>漏洞总数</th>
                <th>风险漏洞</th>
                <th>检测时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="report in historyPagedReports" :key="report.id">
                <td><span class="badge bg-primary">{{ report.id }}</span></td>
                <td>
                  <i class="fas fa-file-alt me-1 text-muted" />{{ report.mac }}
                </td>
                <td>
                  <i class="fas fa-microchip me-1 text-primary" />{{ report.cpu }}
                </td>
                <td>
                  <i class="fas fa-microchip me-1 text-info" />{{ report.architecture }}
                </td>
                <td><code class="text-info">{{ report.kernel }}</code></td>
                <td><span class="badge bg-info">{{ report.vuln_count }}</span></td>
                <td>
                  <span
                    v-if="report.risk_count > 0"
                    class="badge bg-danger"
                    >{{ report.risk_count }}</span
                  >
                  <span v-else class="badge bg-success">0</span>
                </td>
                <td><small class="text-muted">{{ report.report_time }}</small></td>
                <td>
                  <button @click="openDetail(report.mac)" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-eye" /> 查看详情
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <!-- 分页条（历史检测报告） -->
        <nav class="d-flex flex-wrap justify-content-between align-items-center mt-3">
          <!-- 左侧统计 -->
          <div class="text-muted small mb-2 mb-md-0">
            共 {{ historySortedReports.length }} 条，页 {{ historyPage }} / {{ historyTotalPages }}
          </div>

          <!-- 右侧控件：页码 + 每页条数 -->
          <div class="d-flex align-items-center gap-2">
            <ul class="pagination pagination-sm mb-0">
              <li class="page-item" :class="{ disabled: historyPage === 1 }">
                <a class="page-link" href="javascript:void(0)"
                  @click="historyPage > 1 && (historyPage = historyPage - 1)">上一页</a>
              </li>

              <li v-for="p in historyPagesToShow" :key="p"
                  class="page-item" :class="{ active: p === historyPage }">
                <a class="page-link" href="javascript:void(0)" @click="historyPage = p">{{ p }}</a>
              </li>

              <li class="page-item" :class="{ disabled: historyPage === historyTotalPages }">
                <a class="page-link" href="javascript:void(0)"
                  @click="historyPage < historyTotalPages && (historyPage = historyPage + 1)">下一页</a>
              </li>
            </ul>

            <!-- 每页条数（与下方卡片保持一致） -->
            <select v-model.number="historyPageSize" class="form-select form-select-sm w-auto">
              <option :value="6">每页 6</option>
              <option :value="12">每页 12</option>
              <option :value="24">每页 24</option>
            </select>
          </div>
        </nav>

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
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in cves" :key="row.cve">
                <td>{{ row.cve }}</td>
                <td>{{ nameOf(row.cve) }}</td>
                <td>
                  <span v-if="row.affected " class="badge bg-danger">受影响</span>
                  <span v-else class="badge bg-success">安全</span>
                </td>
                <td style="white-space: pre-wrap;">{{ row.info }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </div>
    </div>
    <!-- CVE 防护情况汇总表 -->
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
        <!-- 提示信息 -->
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
      
        <!-- 机器概览 -->
        <div v-if="machines.length" class="row mb-4">
          <div class="d-flex align-items-center flex-wrap mb-3">
            <div class="me-2">
              <h6 class="text-muted mb-0">
                <i class="fas fa-server me-2"></i>已检测机器概览
              </h6>
            </div>
            <!-- 排序工具条-->
            <div class="d-flex align-items-center gap-2 flex-wrap ms-3 ms-md-4 mt-2 mt-md-0">
              <span class="text-muted small me-2">排序：</span>
              <select v-model="sortKey" class="form-select form-select-sm w-auto">
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
            <!-- 搜索框-->
            <div class="ms-auto mt-2 mt-md-0 flex-grow-1" style="max-width: 600px;">
              <input v-model.trim="query" type="text" class="form-control"
                    placeholder="按 MAC / OS / CPU / Kernel / Time 关键字搜索" />
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
                        machine.risk_count > 0 ? 'bg-warning' : 'bg-success'
                      ]"
                      >{{ machine.risk_count > 0 ? machine.risk_count + '风险' : '安全' }}</span
                    >
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 分页条 -->
        <nav class="d-flex flex-wrap justify-content-between align-items-center mt-3">
          <!-- 左侧统计 -->
          <div class="text-muted small mb-2 mb-md-0">
            共 {{ sortedReports.length }} 台，页 {{ page }} / {{ totalPages }}
          </div>

          <!-- 右侧控件：页码 + 每页条数 -->
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

            <!-- 每页条数 -->
            <select v-model.number="pageSize" class="form-select form-select-sm w-auto">
              <option :value="6">每页 6</option>
              <option :value="12">每页 12</option>
              <option :value="24">每页 24</option>
            </select>
          </div>
        </nav>

        <!-- 统计信息卡片 -->
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
                <h5 class="card-title text-success">{{ stats.fully_protected }}</h5>
                <p class="card-text small text-muted">完全防护的CVE</p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card text-center border-warning">
              <div class="card-body">
                <h5 class="card-title text-warning">{{ stats.partially_protected }}</h5>
                <p class="card-text small text-muted">部分防护的CVE</p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card text-center border-danger">
              <div class="card-body">
                <h5 class="card-title text-danger">{{ stats.unprotected }}</h5>
                <p class="card-text small text-muted">未防护的CVE</p>
              </div>
            </div>
          </div>
        </div>

        <!-- 操作建议 -->
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
  </section>
</template>

<script setup>
import { ref, computed, watch, watchEffect, onMounted } from 'vue'
import axios from 'axios'

const reports = ref([])
const machines = ref([])
const vulnerabilities = ref([])
const stats = ref({})
const showInfo = ref(true)   // 初始显示

// ==== 搜索关键字 ====
const query = ref('')
// ② 过滤后的数据（替换 v‑for 用这一份）
const filteredReports = computed(() => {
  // 没输入时直接返回全部
  if (!query.value) return reports.value

  const q = query.value.toLowerCase()
  return reports.value.filter(r => {
    // 按需把字段名改成你真实接口里的键
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
})

// ==== 排序相关 ====
const sortKey = ref('time')   
const sortOrder = ref('asc')  

/** @type {{[k: string]: (m:any) => string}} */
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
    reports.value = res.data.machines
    machines.value = res.data.machines
    vulnerabilities.value = res.data.vulnerabilities
    stats.value = res.data.stats
    console.log('machines', machines.value)
  } catch (e) {
    console.error(e)
  }
}

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
watch([() => query.value, () => sortKey.value, () => sortOrder.value], () => {
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

function toggleHistorySortOrder () {
  historySortOrder.value = historySortOrder.value === 'asc' ? 'desc' : 'asc'
}

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
const historyPageSize = ref(6)

const historyTotalPages = computed(() => {
  const total = historySortedReports.value.length
  return Math.max(1, Math.ceil(total / historyPageSize.value))
})

const historyPagedReports = computed(() => {
  const start = (historyPage.value - 1) * historyPageSize.value
  const end = start + historyPageSize.value
  return historySortedReports.value.slice(start, end)
})

const historyPagesToShow = computed(() => {
  const t = historyTotalPages.value
  const cur = historyPage.value
  const win = 5
  let start = Math.max(1, cur - Math.floor(win / 2))
  let end = Math.min(t, start + win - 1)
  start = Math.max(1, end - win + 1)
  return Array.from({ length: end - start + 1 }, (_, i) => start + i)
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


onMounted(fetchData)
</script>
