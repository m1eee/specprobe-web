<template>
  <section class="container mt-5">
    <div class="d-flex align-items-center mb-3">
      <i class="fas fa-fire text-danger me-2"></i>
      <h4 class="mb-0">firefox收集数据预览</h4>
      <div class="ms-auto" style="max-width: 360px;">

      </div>
    </div>

    <div v-if="loading" class="alert alert-info">加载中...</div>
    <div v-else-if="errorMsg" class="alert alert-danger">{{ errorMsg }}</div>

    <div v-else>
      <div class="card mb-4">
        <div class="card-header2 d-flex align-items-center">
          <i class="fas fa-bookmark me-2"></i>
          <span>书签 ({{ processedBookmarks.length }})</span>
        </div>
        <div class="card-body">
          <div class="mb-3">
            <input v-model="searchBookmark" type="text" class="form-control form-control-sm" placeholder="搜索名称或URL...">
          </div>
          <div class="table-responsive">
            <table class="table table-sm table-hover table-bordered">
              <thead>
                <tr>
                  <th @click="sort('bookmark', 'name')" class="c-pointer">名称 <i :class="getSortIcon('bookmark', 'name')"></i></th>
                  <th style="width: 100px;">类型</th>
                  <th @click="sort('bookmark', 'url')" class="c-pointer">URL <i :class="getSortIcon('bookmark', 'url')"></i></th>
                  <th @click="sort('bookmark', 'date_added')" class="c-pointer" style="width: 200px;">添加时间 <i :class="getSortIcon('bookmark', 'date_added')"></i></th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="b in paginatedBookmarks" :key="b.id">
                  <td class="text-truncate" :title="b.name">{{ b.name }}</td>
                  <td>{{ b.type }}</td>
                  <td><a :href="b.url" target="_blank" rel="noreferrer" class="text-break">{{ b.url }}</a></td>
                  <td>{{ b.date_added }}</td>
                </tr>
                <tr v-if="paginatedBookmarks.length === 0">
                  <td colspan="5" class="text-center text-muted">没有找到匹配的数据</td>
                </tr>
              </tbody>
            </table>
          </div>
          <nav v-if="totalPagesBookmark > 1" class="d-flex justify-content-between align-items-center">
            <div class="text-muted small">第 {{ currentPageBookmark }} / {{ totalPagesBookmark }} 页</div>
            <ul class="pagination pagination-sm mb-0">
              <li class="page-item" :class="{ disabled: currentPageBookmark === 1 }">
                <a class="page-link" href="#" @click.prevent="currentPageBookmark--">&laquo; 上一页</a>
              </li>
              <li class="page-item" :class="{ disabled: currentPageBookmark >= totalPagesBookmark }">
                <a class="page-link" href="#" @click.prevent="currentPageBookmark++">下一页 &raquo;</a>
              </li>
            </ul>
          </nav>
        </div>
      </div>

      <div class="card mb-4">
        <div class="card-header2 d-flex align-items-center">
          <i class="fas fa-cookie-bite me-2"></i>
          <span>Cookie ({{ processedCookies.length }})</span>
        </div>
        <div class="card-body">
            <div class="mb-3">
                <input v-model="searchCookie" type="text" class="form-control form-control-sm" placeholder="搜索Host, Path或Key...">
            </div>
            <div class="table-responsive">
                <table class="table table-sm table-hover table-bordered" style="table-layout: fixed;">
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
                            <th @click="sort('cookie', 'create_date')" class="c-pointer" style="width: 170px;">Create <i :class="getSortIcon('cookie', 'create_date')"></i></th>
                            <th @click="sort('cookie', 'expire_date')" class="c-pointer" style="width: 170px;">Expire <i :class="getSortIcon('cookie', 'expire_date')"></i></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="(c, i) in paginatedCookies" :key="i">
                            <td class="text-truncate" :title="c.host">{{ c.host }}</td>
                            <td class="text-truncate" :title="c.path">{{ c.path }}</td>
                            <td class="text-truncate" :title="c.key_name">{{ c.key_name }}</td>
                            <td class="text-truncate" :title="c.value">{{ c.value }}</td>
                            <td>{{ c.is_secure ? '是' : '否' }}</td>
                            <td>{{ c.is_http_only ? '是' : '否' }}</td>
                            <td>{{ c.has_expire ? '是' : '否' }}</td>
                            <td>{{ c.is_persistent ? '是' : '否' }}</td>
                            <td>{{ c.create_date }}</td>
                            <td>{{ c.expire_date }}</td>
                        </tr>
                        <tr v-if="paginatedCookies.length === 0">
                            <td colspan="10" class="text-center text-muted">没有找到匹配的数据</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <nav v-if="totalPagesCookie > 1" class="d-flex justify-content-between align-items-center">
                <div class="text-muted small">第 {{ currentPageCookie }} / {{ totalPagesCookie }} 页</div>
                <ul class="pagination pagination-sm mb-0">
                    <li class="page-item" :class="{ disabled: currentPageCookie === 1 }">
                        <a class="page-link" href="#" @click.prevent="currentPageCookie--">&laquo; 上一页</a>
                    </li>
                    <li class="page-item" :class="{ disabled: currentPageCookie >= totalPagesCookie }">
                        <a class="page-link" href="#" @click.prevent="currentPageCookie++">下一页 &raquo;</a>
                    </li>
                </ul>
            </nav>
        </div>
      </div>

      <div class="card mb-4">
        <div class="card-header2 d-flex align-items-center">
          <i class="fas fa-history me-2"></i>
          <span>历史记录 ({{ processedHistory.length }})</span>
        </div>
        <div class="card-body">
            <div class="mb-3">
                <input v-model="searchHistory" type="text" class="form-control form-control-sm" placeholder="搜索标题或URL...">
            </div>
            <div class="table-responsive">
                <table class="table table-sm table-hover table-bordered">
                    <thead>
                    <tr>
                        <th @click="sort('history', 'title')" class="c-pointer">标题 <i :class="getSortIcon('history', 'title')"></i></th>
                        <th @click="sort('history', 'url')" class="c-pointer">URL <i :class="getSortIcon('history', 'url')"></i></th>
                        <th @click="sort('history', 'visit_count')" class="c-pointer" style="width: 100px;">访问次数 <i :class="getSortIcon('history', 'visit_count')"></i></th>
                        <th @click="sort('history', 'last_visit_time')" class="c-pointer" style="width: 200px;">最近访问 <i :class="getSortIcon('history', 'last_visit_time')"></i></th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr v-for="(r, i) in paginatedHistory" :key="i">
                        <td class="text-truncate" :title="r.title">{{ r.title }}</td>
                        <td><a :href="r.url" target="_blank" rel="noreferrer" class="text-break">{{ r.url }}</a></td>
                        <td>{{ r.visit_count }}</td>
                        <td>{{ r.last_visit_time }}</td>
                    </tr>
                    <tr v-if="paginatedHistory.length === 0">
                        <td colspan="4" class="text-center text-muted">没有找到匹配的数据</td>
                    </tr>
                    </tbody>
                </table>
            </div>
            <nav v-if="totalPagesHistory > 1" class="d-flex justify-content-between align-items-center">
                <div class="text-muted small">第 {{ currentPageHistory }} / {{ totalPagesHistory }} 页</div>
                <ul class="pagination pagination-sm mb-0">
                    <li class="page-item" :class="{ disabled: currentPageHistory === 1 }">
                        <a class="page-link" href="#" @click.prevent="currentPageHistory--">&laquo; 上一页</a>
                    </li>
                    <li class="page-item" :class="{ disabled: currentPageHistory >= totalPagesHistory }">
                        <a class="page-link" href="#" @click.prevent="currentPageHistory++">下一页 &raquo;</a>
                    </li>
                </ul>
            </nav>
        </div>
      </div>

    </div>
  </section>
</template>

<script setup>
import { ref, onMounted, computed, watch } from 'vue'
import axios from 'axios'

// --- Base State ---
const bookmark = ref([])
const cookie = ref([])
const history = ref([])
const loading = ref(false)
const errorMsg = ref('')
const subdir = ref('')

// --- Data Fetching ---
async function fetchData() {
  loading.value = true
  errorMsg.value = ''
  bookmark.value = []; cookie.value = []; history.value = [];
  try {
    const url = subdir.value
      ? `/api/attack/data/?subdir=${encodeURIComponent(subdir.value)}`
      : `/api/attack/data/`
    const { data } = await axios.get(url)
    bookmark.value = data.bookmark || []
    cookie.value = data.cookie || []
    history.value = data.history || []
  } catch (err) {
    console.error(err)
    errorMsg.value = err.response?.data?.error || err.message || '获取数据时发生未知错误'
  } finally {
    loading.value = false
  }
}

onMounted(fetchData)

// --- Table Interaction State ---
const pageSize = 10;

// Bookmarks state
const searchBookmark = ref('')
const sortKeyBookmark = ref('date_added')
const sortDirBookmark = ref('desc')
const currentPageBookmark = ref(1)

// Cookies state
const searchCookie = ref('')
const sortKeyCookie = ref('create_date')
const sortDirCookie = ref('desc')
const currentPageCookie = ref(1)

// History state
const searchHistory = ref('')
const sortKeyHistory = ref('last_visit_time')
const sortDirHistory = ref('desc')
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

    data.sort((a, b) => {
      const key = sortKeyRef.value;
      let valA = a[key];
      let valB = b[key];
      
      if (numericSortFields.includes(key)) {
          valA = Number(valA) || 0;
          valB = Number(valB) || 0;
      }

      const modifier = sortDirRef.value === 'asc' ? 1 : -1;
      if (valA < valB) return -1 * modifier;
      if (valA > valB) return 1 * modifier;
      return 0;
    });

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

<style>
.c-pointer {
  cursor: pointer;
  user-select: none;
}
.table-bordered {
    border: 1px solid #dee2e6;
}

.card-header2 {
    background: linear-gradient(to right, #e65100, #ffa726);
    color: white;
    font-weight: 600;
    border-bottom: none;
    padding: 1rem 1.5rem;
}
</style>