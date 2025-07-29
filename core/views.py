from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.files.storage import default_storage
from django.conf import settings
from pathlib import Path
from .utils import calculate_protection_stats
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
import json
from core.models import MachineReport
from django.http import JsonResponse, HttpResponseNotAllowed
from core.utils import calculate_protection_stats  # 你的统计函数
from django.utils import timezone
from .serializers import MachineReportSerializer
REQUIRED_FIELDS = [
    "mac", "status", "cpu", "kernel", "os", "architecture",
    "vuln_count", "risk_count", "time"
]

def _parse_time(value):
    """把 time 转成有时区的 datetime（兼容 ISO8601 / 'YYYY-MM-DD HH:MM:SS' / 时间戳）"""
    if isinstance(value, (int, float)):  # unix 时间戳（秒）
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        if s.endswith("Z"):  # 处理末尾 Z
            s = s[:-1] + "+00:00"
        # ISO8601
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            return dt
        except Exception:
            pass
        # "YYYY-MM-DD HH:MM:SS"
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        return timezone.make_aware(dt, timezone.get_current_timezone())
    raise ValueError("Unsupported time format")

def _normalize_item(data: dict) -> dict:
    """字段标准化 + 基本校验"""
    row = dict(data)
    row.pop("id", None)  # 不允许外部 id 覆盖自增主键
    missing = [k for k in REQUIRED_FIELDS if k not in row]
    if missing:
        raise ValueError(f"缺少必需字段: {', '.join(missing)}")
    row["vuln_count"] = int(row["vuln_count"])
    row["risk_count"] = int(row["risk_count"])
    row["time"] = _parse_time(row["time"])
    return row

def _ensure_list(payload):
    """把 payload 变成 list；支持单对象或数组"""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise ValueError("请求体必须为 JSON 对象或对象数组")

def reports(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(permitted_methods=["GET"])
    data = calculate_protection_stats()
    # data 是字典，默认 safe=True 只允许 dict；设为 True/不写都可以
    return JsonResponse(data)

class UploadReportView(APIView):
    def post(self, request):
        # ① 取上传文件
        f = request.FILES.get("file")
        if not f or not f.name.endswith(".json"):
            return Response({"detail": "请上传 .json 报告"}, status=status.HTTP_400_BAD_REQUEST)

        # ② 解析 JSON 到 Python dict
        report_dict = json.load(f)

        # ④ 用序列化器校验 + 保存
        ser = MachineReportSerializer(data=report_dict)
        if ser.is_valid():
            ser.save()                 # ⚠️ 这一步才会写入 machine_report 表
            return Response(ser.data, status=status.HTTP_201_CREATED)
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)
class ReportStatsView(APIView):
    def get(self, request):
        return Response(calculate_protection_stats())

class DashboardDataView(APIView):
    def get(self, request):
        data = calculate_protection_stats()
        # 这里返回 CPU / CVSS 等汇总，同 Flask /api/stats 路由 :contentReference[oaicite:5]{index=5}
        return Response(data["stats"])

@api_view(["POST"])
@parser_classes([JSONParser, MultiPartParser, FormParser])
def import_report(request):
    """
    导入 MachineReport：
    - 直接 POST JSON：对象或数组
    - 或 multipart/form-data 上传一个 .json 文件（字段名 file）
    以 (filename, time) 作为“唯一键”，执行 update_or_create（UPSERT）
    """
    # 1) 读取 payload
    try:
        if "file" in request.FILES:
            # 兼容带 BOM 的 JSON：utf-8-sig
            raw = request.FILES["file"].read().decode("utf-8-sig")
            payload = json.loads(raw)
        else:
            # DRF 已把 JSON 解析成 Python 对象（dict/list）
            payload = request.data
    except Exception as e:
        return Response({"detail": f"JSON 解析失败: {e}"}, status=status.HTTP_400_BAD_REQUEST)

    # 2) 逐条处理（这里选择“部分成功”策略；如需全-or-无，可把 for 包在 transaction.atomic() 里）
    results, errors = [], []
    created_count = updated_count = 0

    try:
        items = _ensure_list(payload)
    except Exception as e:
        return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    for idx, item in enumerate(items):
        try:
            row = _normalize_item(item)
            lookup = {"mac": row["mac"], "time": row["time"]}
            defaults = {k: v for k, v in row.items() if k not in lookup}
            obj, created = MachineReport.objects.update_or_create(**lookup, defaults=defaults)
            results.append({"index": idx, "id": obj.id, "mac": obj.mac, "created": created})
            created_count += int(created)
            updated_count += int(not created)
        except Exception as e:
            errors.append({"index": idx, "error": str(e)})

    http_status = status.HTTP_201_CREATED if created_count and not updated_count and not errors else status.HTTP_200_OK
    return Response({
        "created": created_count,
        "updated": updated_count,
        "failed": len(errors),
        "results": results,
        "errors": errors
    }, status=http_status)