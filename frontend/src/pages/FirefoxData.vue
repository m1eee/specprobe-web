<template>
  <div style="background-color: black;">
  <main class="main-container">
    <div class="page-title-container">
      <i class="fas fa-fire-alt me-3"></i>
      <h1 class="page-title">Firefox_Data_Stream // 收集数据预览</h1>
    </div>

    <div v-if="loading" class="terminal-loader">
      &gt; Accessing data stream...
      <span class="cursor">_</span>
    </div>
    <div v-else-if="errorMsg" class="alert-error">
      &gt; <span class="error-tag">[ERROR]</span>: Connection to target lost. {{ errorMsg }}
    </div>

    <div v-else class="data-grid">
      <div class="data-panel">
        <div class="panel-header">
          <i class="fas fa-bookmark me-2"></i>
          <span>Bookmarks_Log [{{ processedBookmarks.length }}]</span>
        </div>
        <div class="panel-body">
          <input v-model="searchBookmark" type="text" class="filter-input" placeholder="filter by name or url...">
          <div class="table-responsive">
            <table class="data-table">
              <thead>
                <tr>
                  <th @click="sort('bookmark', 'name')" class="c-pointer">Name <i :class="getSortIcon('bookmark', 'name')"></i></th>
                  <th style="width: 100px;">Type</th>
                  <th @click="sort('bookmark', 'url')" class="c-pointer">URL <i :class="getSortIcon('bookmark', 'url')"></i></th>
                  <th @click="sort('bookmark', 'date_added')" class="c-pointer" style="width: 200px;">Date Added <i :class="getSortIcon('bookmark', 'date_added')"></i></th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="b in paginatedBookmarks" :key="b.id" :class="{'new-data-entry': b.isNew}">
                  <td :class="{'row-new': b.isNew}" :title="b.name">{{ b.name }}</td>
                  <td :class="{'row-new': b.isNew}">{{ b.type }}</td>
                  <td :class="{'row-new': b.isNew}"><a :href="b.url" target="_blank" rel="noreferrer" class="text-break">{{ b.url }}</a></td>
                  <td :class="{'row-new': b.isNew}">{{ b.date_added }}</td>
                </tr>
                <tr v-if="paginatedBookmarks.length === 0">
                  <td colspan="4" class="no-data">// no matching entries</td>
                </tr>
              </tbody>
            </table>
          </div>
          <nav v-if="totalPagesBookmark > 1" class="pagination-container">
            <div class="page-info">Page {{ currentPageBookmark }} / {{ totalPagesBookmark }}</div>
            <div class="pagination-controls">
              <a href="#" @click.prevent="currentPageBookmark--" :class="{ disabled: currentPageBookmark === 1 }">&lt;&lt; PREV</a>
              <a href="#" @click.prevent="currentPageBookmark++" :class="{ disabled: currentPageBookmark >= totalPagesBookmark }">NEXT &gt;&gt;</a>
            </div>
          </nav>
        </div>
      </div>

      <div class="data-panel">
        <div class="panel-header">
          <i class="fas fa-cookie-bite me-2"></i>
          <span>Cookie_Jar [{{ processedCookies.length }}]</span>
        </div>
        <div class="panel-body">
            <input v-model="searchCookie" type="text" class="filter-input" placeholder="filter by host, path or key...">
            <div class="table-responsive">
                <table class="data-table wide">
                    <thead>
                        <tr>
                            <th @click="sort('cookie', 'host')" class="c-pointer" style="width: 180px;">Host <i :class="getSortIcon('cookie', 'host')"></i></th>
                            <th style="width: 120px;">Path</th>
                            <th @click="sort('cookie', 'key_name')" class="c-pointer" style="width: 180px;">Key <i :class="getSortIcon('cookie', 'key_name')"></i></th>
                            <th style="width: 200px;">Value</th>
                            <th style="width: 80px;">Secure</th>
                            <th style="width: 90px;">HTTPOnly</th>
                            <th style="width: 95px;">HasExpire</th>
                            <th style="width: 95px;">Persistent</th>
                            <th @click="sort('cookie', 'create_date')" class="c-pointer" style="width: 170px;">Created <i :class="getSortIcon('cookie', 'create_date')"></i></th>
                            <th @click="sort('cookie', 'expire_date')" class="c-pointer" style="width: 170px;">Expires <i :class="getSortIcon('cookie', 'expire_date')"></i></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="(c, i) in paginatedCookies" :key="i" :class="{'new-data-entry': c.isNew}">
                            <td :class="{'row-new': c.isNew}" :title="c.host">{{ c.host }}</td>
                            <td :class="{'row-new': c.isNew}" :title="c.path">{{ c.path }}</td>
                            <td :class="{'row-new': c.isNew}" :title="c.key_name">{{ c.key_name }}</td>
                            <td :class="{'row-new': c.isNew}" :title="c.value">{{ c.value }}</td>
                            <td :class="{'row-new': c.isNew}">{{ c.is_secure ? '是' : '否' }}</td>
                            <td :class="{'row-new': c.isNew}">{{ c.is_http_only ? '是' : '否' }}</td>
                            <td :class="{'row-new': c.isNew}">{{ c.has_expire ? '是' : '否' }}</td>
                            <td :class="{'row-new': c.isNew}">{{ c.is_persistent ? '是' : '否' }}</td>
                            <td :class="{'row-new': c.isNew}">{{ c.create_date }}</td>
                            <td :class="{'row-new': c.isNew}">{{ c.expire_date }}</td>
                        </tr>
                        <tr v-if="paginatedCookies.length === 0">
                            <td colspan="10" class="no-data">// no matching entries</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <nav v-if="totalPagesCookie > 1" class="pagination-container">
              <div class="page-info">Page {{ currentPageCookie }} / {{ totalPagesCookie }}</div>
              <div class="pagination-controls">
                <a href="#" @click.prevent="currentPageCookie--" :class="{ disabled: currentPageCookie === 1 }">&lt;&lt; PREV</a>
                <a href="#" @click.prevent="currentPageCookie++" :class="{ disabled: currentPageCookie >= totalPagesCookie }">NEXT &gt;&gt;</a>
              </div>
            </nav>
        </div>
      </div>

      <div class="data-panel">
        <div class="panel-header">
          <i class="fas fa-history me-2"></i>
          <span>History_Log [{{ processedHistory.length }}]</span>
        </div>
        <div class="panel-body">
            <input v-model="searchHistory" type="text" class="filter-input" placeholder="filter by title or url...">
            <div class="table-responsive">
                <table class="data-table">
                    <thead>
                    <tr>
                        <th @click="sort('history', 'title')" class="c-pointer">Title <i :class="getSortIcon('history', 'title')"></i></th>
                        <th @click="sort('history', 'url')" class="c-pointer">URL <i :class="getSortIcon('history', 'url')"></i></th>
                        <th @click="sort('history', 'visit_count')" class="c-pointer" style="width: 100px;">Visits <i :class="getSortIcon('history', 'visit_count')"></i></th>
                        <th @click="sort('history', 'last_visit_time')" class="c-pointer" style="width: 200px;">Last Visit <i :class="getSortIcon('history', 'last_visit_time')"></i></th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr v-for="(r, i) in paginatedHistory" :key="i" :class="{'new-data-entry': r.isNew}">
                        <td :class="{'row-new': r.isNew}" :title="r.title">{{ r.title }}</td>
                        <td :class="{'row-new': r.isNew}"><a :href="r.url" target="_blank" rel="noreferrer" class="text-break">{{ r.url }}</a></td>
                        <td :class="{'row-new': r.isNew}">{{ r.visit_count }}</td>
                        <td :class="{'row-new': r.isNew}">{{ r.last_visit_time }}</td>
                    </tr>
                    <tr v-if="paginatedHistory.length === 0">
                        <td colspan="4" class="no-data">// no matching entries</td>
                    </tr>
                    </tbody>
                </table>
            </div>
             <nav v-if="totalPagesHistory > 1" class="pagination-container">
                <div class="page-info">Page {{ currentPageHistory }} / {{ totalPagesHistory }}</div>
                <div class="pagination-controls">
                  <a href="#" @click.prevent="currentPageHistory--" :class="{ disabled: currentPageHistory === 1 }">&lt;&lt; PREV</a>
                  <a href="#" @click.prevent="currentPageHistory++" :class="{ disabled: currentPageHistory >= totalPagesHistory }">NEXT &gt;&gt;</a>
                </div>
            </nav>
        </div>
      </div>
    </div>
  </main>
</div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import axios from 'axios'

// --- 定时器ID ---
let pollingIntervalId = null;

// --- Base State ---
const bookmark = ref([])
const cookie = ref([])
const history = ref([])
const loading = ref(false)
const errorMsg = ref('')
const subdir = ref('')

// --- Data Fetching ---
async function fetchData() {
  errorMsg.value = ''
  try {
    const url = subdir.value
      ? `/api/attack/data/?subdir=${encodeURIComponent(subdir.value)}`
      : `/api/attack/data/`
    const { data } = await axios.get(url)
    bookmark.value = [
      ...(data.bookmark      ?? []).map(r => ({ ...r, isNew: true })),
      ...(data.bookmark_old  ?? []).map(r => ({ ...r, isNew: false }))
    ]
    cookie.value = [
      ...(data.cookie        ?? []).map(r => ({ ...r, isNew: true })),
      ...(data.cookie_old    ?? []).map(r => ({ ...r, isNew: false }))
    ]
    history.value = [
      ...(data.history       ?? []).map(r => ({ ...r, isNew: true })),
      ...(data.history_old   ?? []).map(r => ({ ...r, isNew: false }))
    ]
  } catch (err) {
    console.error(err)
    errorMsg.value = err.response?.data?.error || err.message || '获取数据时发生未知错误'
    if (pollingIntervalId) {
      clearInterval(pollingIntervalId);
    }
  }
}

onMounted(() => {
  loading.value = true;
  fetchData().finally(() => {
    loading.value = false;
  });

  const pollFrequency = 1000;
  pollingIntervalId = setInterval(fetchData, pollFrequency);
});

onUnmounted(() => {
  if (pollingIntervalId) {
    clearInterval(pollingIntervalId);
  }
});


// --- Table Interaction State ---
const pageSize = 10;

// Bookmarks state
const searchBookmark = ref('')
const sortKeyBookmark = ref('')
const sortDirBookmark = ref('asc')
const currentPageBookmark = ref(1)

// Cookies state
const searchCookie = ref('')
const sortKeyCookie = ref('')
const sortDirCookie = ref('asc')
const currentPageCookie = ref(1)

// History state
const searchHistory = ref('')
const sortKeyHistory = ref('')
const sortDirHistory = ref('asc')
const currentPageHistory = ref(1)

// --- Computed Properties for Data Processing ---
const createTableProcessor = (sourceData, searchRef, sortKeyRef, sortDirRef, searchFields, numericSortFields = []) => {
  return computed(() => {
    let data = [...(sourceData.value || [])];
    const query = searchRef.value.toLowerCase().trim();

    if (query) {
      data = data.filter(item =>
        searchFields.some(field =>
          item[field]?.toString().toLowerCase().includes(query)
        )
      );
    }

  if (sortKeyRef.value) {
    data.sort((a, b) => {
      const key = sortKeyRef.value
      let valA = a[key]
      let valB = b[key]

      if (numericSortFields.includes(key)) {
        valA = Number(valA) || 0
        valB = Number(valB) || 0
      }

      const modifier = sortDirRef.value === 'asc' ? 1 : -1
      if (valA < valB) return -1 * modifier
      if (valA > valB) return  1 * modifier
      return 0
    });
  }

    return data;
  });
};

const processedBookmarks = createTableProcessor(bookmark, searchBookmark, sortKeyBookmark, sortDirBookmark, ['name', 'url']);
const processedCookies = createTableProcessor(cookie, searchCookie, sortKeyCookie, sortDirCookie, ['host', 'path', 'key_name']);
const processedHistory = createTableProcessor(history, searchHistory, sortKeyHistory, sortDirHistory, ['title', 'url'], ['visit_count']);

// Pagination Computeds
const totalPagesBookmark = computed(() => Math.ceil(processedBookmarks.value.length / pageSize));
const paginatedBookmarks = computed(() => {
  const start = (currentPageBookmark.value - 1) * pageSize;
  return processedBookmarks.value.slice(start, start + pageSize);
});

const totalPagesCookie = computed(() => Math.ceil(processedCookies.value.length / pageSize));
const paginatedCookies = computed(() => {
  const start = (currentPageCookie.value - 1) * pageSize;
  return processedCookies.value.slice(start, start + pageSize);
});

const totalPagesHistory = computed(() => Math.ceil(processedHistory.value.length / pageSize));
const paginatedHistory = computed(() => {
  const start = (currentPageHistory.value - 1) * pageSize;
  return processedHistory.value.slice(start, start + pageSize);
});


// --- Watchers to reset page on search/filter change ---
watch(searchBookmark, () => { currentPageBookmark.value = 1; });
watch(searchCookie, () => { currentPageCookie.value = 1; });
watch(searchHistory, () => { currentPageHistory.value = 1; });

// --- Generic Methods ---
function sort(type, key) {
  const stateMap = {
    bookmark: { key: sortKeyBookmark, dir: sortDirBookmark, page: currentPageBookmark },
    cookie:   { key: sortKeyCookie,   dir: sortDirCookie,   page: currentPageCookie   },
    history:  { key: sortKeyHistory,  dir: sortDirHistory,  page: currentPageHistory  },
  };
  const state = stateMap[type];
  if (!state) return;

  if (state.key.value === key) {
    state.dir.value = state.dir.value === 'asc' ? 'desc' : 'asc';
  } else {
    state.key.value = key;
    state.dir.value = 'asc';
  }
  state.page.value = 1; 
}

function getSortIcon(type, key) {
  const stateMap = {
    bookmark: { key: sortKeyBookmark.value, dir: sortDirBookmark.value },
    cookie:   { key: sortKeyCookie.value,   dir: sortDirCookie.value   },
    history:  { key: sortKeyHistory.value,  dir: sortDirHistory.value  },
  };
  const state = stateMap[type];

  if (key !== state.key) return 'fas fa-sort text-muted';
  return state.dir === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down';
}


</script>

<style scoped>
/* It's best to set global styles in a main CSS file (e.g., main.css or App.vue) 
  to ensure a consistent background and font across the entire application.
*/
body {
  background-color: #0A0A0A !important;
  color: #E0E0E0 !important;
  font-family: 'Fira Code', monospace !important;
}

@keyframes pop-in {
  0% {
    opacity: 0;
    transform: scale(0.9);
    background-color: rgba(0, 255, 65, 0.2);
  }
  70% {
    background-color: rgba(0, 255, 65, 0.05);
  }
  100% {
    opacity: 1;
    transform: scale(1);
    background-color: transparent;
  }
}

@keyframes blink {
  50% { opacity: 0; }
}

.main-container {
  padding: 2rem;
  font-family: 'Fira Code', monospace;
  color: #E0E0E0;
}

.page-title-container {
  display: flex;
  align-items: center;
  color: #00ff41;
  text-shadow: 0 0 8px rgba(0, 255, 65, 0.5);
  margin-bottom: 2rem;
  font-size: 1.5rem;
  border-bottom: 1px solid #00ff41;
  padding-bottom: 1rem;
}
.page-title {
  font-size: inherit;
  margin: 0;
  font-weight: 700;
}

/* --- Loader and Error States --- */
.terminal-loader, .alert-error {
  border: 1px solid #00ff41;
  background-color: #111;
  padding: 2rem;
  font-size: 1.2rem;
  color: #00ff41;
}
.terminal-loader .cursor {
  animation: blink 1s step-end infinite;
}
.alert-error {
  border-color: #ff4141;
  color: #ff4141;
}
.alert-error .error-tag {
  background-color: #ff4141;
  color: #0A0A0A;
  padding: 2px 6px;
  font-weight: bold;
}

/* --- Data Panels --- */
.data-grid {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}
.data-panel {
  border: 1px solid #00ff41;
  background-color: #0D0D0D;
  box-shadow: 0 0 15px rgba(0, 255, 65, 0.15);
  display: flex;
  flex-direction: column;
}

.panel-header {
  background-color: #00ff41;
  color: #0A0A0A;
  font-weight: 700;
  padding: 0.75rem 1rem;
  display: flex;
  align-items: center;
  letter-spacing: 1px;
}

.panel-body {
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.filter-input {
  background-color: #1a1a1a;
  border: 1px solid #444;
  color: #E0E0E0;
  padding: 0.5rem 1rem;
  font-family: inherit;
  width: 100%;
}
.filter-input:focus {
  outline: none;
  border-color: #00ff41;
  box-shadow: 0 0 5px rgba(0, 255, 65, 0.5);
}
.filter-input::placeholder {
    color: #666;
}

/* --- Table Styles --- */
.table-responsive {
  overflow-x: auto;
}
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
.data-table th, .data-table td {
  padding: 0.6rem 0.8rem;
  text-align: left;
  border-bottom: 1px solid #333;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 250px;
}
.data-table.wide td {
  max-width: 180px;
}
.data-table td.value-cell {
  max-width: 220px;
}

.data-table th {
  color: #00ff41;
  font-weight: 700;
  border-bottom: 2px solid #00ff41;
}
.c-pointer {
  cursor: pointer;
  user-select: none;
}
.c-pointer:hover, .data-table th .fa-sort:hover {
  color: #9effb8;
}
.text-muted {
  color: #666 !important;
}

.data-table td a {
  color: #4db8ff;
  text-decoration: none;
  font-weight: bold;
}
.data-table td a:hover {
  text-decoration: underline;
  color: #8ad0ff;
}

.new-data-entry {
  animation: pop-in 0.6s ease-out forwards;
}
.no-data {
    text-align: center !important;
    color: #777;
    font-style: italic;
    padding: 1.5rem;
}

/* --- Custom Pagination Styles --- */
.pagination-container {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-top: 1rem;
  font-size: 0.9rem;
  border-top: 1px solid #333;
  margin-top: 0.5rem;
}
.page-info {
  color: #888;
}
.pagination-controls a {
  color: #00ff41;
  text-decoration: none;
  padding: 0.3rem 0.8rem;
  border: 1px solid #00ff41;
  margin-left: 0.5rem;
  transition: background-color 0.2s, color 0.2s;
}
.pagination-controls a:hover {
  background-color: rgba(0, 255, 65, 0.2);
}
.pagination-controls a.disabled {
  color: #555;
  border-color: #555;
  pointer-events: none;
}
.row-new {
  background: #33312e !important;
}
</style>