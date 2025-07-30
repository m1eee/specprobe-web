import { createRouter, createWebHistory } from "vue-router";
import Dashboard from "@/pages/Dashboard.vue";
import Upload from "@/pages/Upload.vue";
import Charts from "@/pages/Charts.vue";
import Reports from "@/pages/Reports.vue";
import Results from "@/pages/Results.vue";
import Settings from "@/pages/Settings.vue";
export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: Dashboard },
    { path: "/upload", component: Upload },
    { path: '/charts', component: Charts },
    { path: '/reports', component: Reports },
    { path: '/results', component: Results },
    { path: '/settings', component: Settings },
    { path: '/firefox', component: () => import('@/pages/FirefoxData.vue') },
  ]
});
