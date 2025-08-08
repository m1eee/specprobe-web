import { createRouter, createWebHistory } from "vue-router";
import LayoutDefault from '@/layouts/LayoutDefault.vue'
import LayoutBlank from '@/layouts/LayoutBlank.vue'
import Dashboard from "@/pages/Dashboard.vue";
import Upload from "@/pages/Upload.vue";
import Charts from "@/pages/Charts.vue";
import Charts2 from "@/pages/Charts2.vue";
import Reports from "@/pages/Reports.vue";
import Results from "@/pages/Results.vue";
import Settings from "@/pages/Settings.vue";
import Attack from "@/pages/FirefoxData.vue";
export default createRouter({
  history: createWebHistory(),
  routes: [
  {
    path: '/',
    component: LayoutDefault,
    children: [
      { path: "/", component: Dashboard },
      { path: "/upload", component: Upload },
      { path: '/charts1', component: Charts },
      { path: '/charts2', component: Charts2 },
      { path: '/reports', component: Reports },
      { path: '/results', component: Results },
      { path: '/settings', component: Settings },

    ],
  },
  {
    path: '/attack',
    component: LayoutBlank,
    children: [{ path: '', component: Attack }],
  },
  ]
});

