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
                <th>系统版本</th>
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
                <td style="width: 15%;">
                  <i class="fas fa-microchip me-1 text-primary" />{{ report.cpu }}
                </td>
                <td>
                  <i class="fas fa-desktop me-1 text-info" />{{ report.os }}
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
                <td style="width: 10%;"><small class="text-muted">{{ report.report_time }}</small></td>
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
import axios from 'axios'

const reports = ref([])
const machines = ref([])
const vulnerabilities = ref([])
const stats = ref({})

// ==== 搜索关键字 ====
const query = ref('')
// ② 过滤后的数据（替换 v‑for 用这一份）
const filteredReports = computed(() => {
  // 没输入时直接返回全部
  if (!query.value) return reports.value

  const q = query.value.toLowerCase()
  return reports.value.filter(r => {
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
    console.log('reports', res.data)
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
const pageSize = ref(12)       // 每页条数（建议 6/12/24 等）

// 总页数
const totalPages = computed(() => {
  const total = sortedReports.value.length
  return Math.max(1, Math.ceil(total / pageSize.value))
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
function getMitigationLines(text) {
  if (!text) return [];
  // 按换行符分割，并过滤掉可能存在的空行
  return text.split('\n').filter(line => line.trim() !== '');
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
const historyPageSize = ref(12)

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


onMounted(fetchData)
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