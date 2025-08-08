
<template>
  <footer class="footer footer--orange">
    <div class="container">
      <div class="row">
        <!-- 品牌简介 -->
        <div class="col-md-4 mb-4 mb-md-0">
          <h5 class="text-white mb-3">SpecProbe-Attack</h5>
          <p>漏洞攻击演示平台，直观展示系统安全风险。</p>
          <div class="d-flex gap-2">
            <a href="#" class="text-white"><i class="fab fa-github fa-lg" /></a>
            <a href="#" class="text-white"><i class="fab fa-twitter fa-lg" /></a>
            <a href="#" class="text-white"><i class="fab fa-linkedin fa-lg" /></a>
          </div>
        </div>

        <!-- 快速链接 -->
        <div class="col-md-4 mb-4 mb-md-0">
          <h5 class="text-white mb-3">快速链接</h5>
          <ul class="list-unstyled">
            <li><RouterLink to="/" class="text-white-50">下载检测工具</RouterLink></li>
            <li><a href="#" class="text-white-50">文档中心</a></li>
            <li><a href="#" class="text-white-50">API接口</a></li>
            <li><a href="#" class="text-white-50">漏洞数据库</a></li>
          </ul>
        </div>
      </div>

      <hr class="bg-light my-4" />
      <div class="text-center text-white-50">
        &copy; 2025 SpecProbe. 保留所有权利。
      </div>
    </div>
  </footer>
</template>


<style scoped>
.footer {
  margin-top: 0 !important;   /* 清掉那 3 rem 左右的默认外边距 */
}
.footer--orange {
  background: linear-gradient(135deg, #0f0601 0%, #000000 45%, #000000 100%);
}
.footer--orange a { color: rgba(0, 0, 0, 0.85); }
.footer--orange a:hover { opacity: 1; transition: opacity .2s ease; }
.footer--orange :deep(hr) {
  border-top-color: rgba(0, 0, 0, 0.25);
  opacity: .5;
}
</style>
