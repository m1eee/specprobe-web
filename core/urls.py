from django.urls import path
from core import views as core_views
from core.views import import_report

urlpatterns = [
    path("api/upload/", core_views.UploadReportView.as_view()),
    path("api/reports/", core_views.ReportStatsView.as_view()),
    path("api/stats/", core_views.DashboardDataView.as_view()),
]


urlpatterns = [
    path("api/import-report/", import_report),
]
