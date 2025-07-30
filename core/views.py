from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from pathlib import Path
from .utils import calculate_protection_stats
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
import json
from core.models import MachineReport, DeviceVulnSnapshot
from django.http import JsonResponse, HttpResponseNotAllowed
from core.utils import calculate_protection_stats 
from django.utils import timezone
from .serializers import MachineReportSerializer
from django.shortcuts import get_object_or_404

REQUIRED_FIELDS = [
    "mac", "status", "cpu", "kernel", "os", "architecture",
    "vuln_count", "risk_count", "time"
]
CVE_TO_FIELD = {
    "CVE-2017-5753": "cve_2017_5753",
    "CVE-2017-5715": "cve_2017_5715",
    "CVE-2017-5754": "cve_2017_5754",
    "CVE-2018-3640": "cve_2018_3640",
    "CVE-2018-3639": "cve_2018_3639",
    "CVE-2018-3615": "cve_2018_3615",
    "CVE-2018-3620": "cve_2018_3620",
    "CVE-2018-3646": "cve_2018_3646",
    "CVE-2018-12126": "cve_2018_12126",
    "CVE-2018-12130": "cve_2018_12130",
    "CVE-2018-12127": "cve_2018_12127",
    "CVE-2019-11091": "cve_2019_11091",
    "CVE-2019-11135": "cve_2019_11135",
    "CVE-2018-12207": "cve_2018_12207",
    "CVE-2020-0543":  "cve_2020_0543",
    "CVE-2023-20593": "cve_2023_20593",
    "CVE-2022-40982": "cve_2022_40982",
    "CVE-2022-4543":"cve_2022_4543",
    "CVE-2023-20569": "cve_2023_20569",
    "CVE-2023-23583": "cve_2023_23583",
}
CVE_TO_INFO_FIELD = {
    "CVE-2017-5753": "cve_2017_5753_info",
    "CVE-2017-5715": "cve_2017_5715_info",
    "CVE-2017-5754": "cve_2017_5754_info",
    "CVE-2018-3640": "cve_2018_3640_info",
    "CVE-2018-3639": "cve_2018_3639_info",
    "CVE-2018-3615": "cve_2018_3615_info",
    "CVE-2018-3620": "cve_2018_3620_info",
    "CVE-2018-3646": "cve_2018_3646_info",
    "CVE-2018-12126": "cve_2018_12126_info",
    "CVE-2018-12130": "cve_2018_12130_info",
    "CVE-2018-12127": "cve_2018_12127_info",
    "CVE-2019-11091": "cve_2019_11091_info",
    "CVE-2019-11135": "cve_2019_11135_info",
    "CVE-2018-12207": "cve_2018_12207_info",
    "CVE-2020-0543":  "cve_2020_0543_info",
    "CVE-2023-20593": "cve_2023_20593_info",
    "CVE-2022-40982": "cve_2022_40982_info",
    "CVE-2022-4543":"cve_2022_4543_info",
    "CVE-2023-20569": "cve_2023_20569_info",
    "CVE-2023-23583": "cve_2023_23583_info",
}
def upsert_vuln_snapshot(mac: str, vulns: list[dict]):
    """
    将前端传来的 20 项漏洞数组打存到宽表
    """
    defaults = {}
    for it in vulns or []:
        cve = (it.get("CVE") or "").strip().upper()
        field = CVE_TO_FIELD.get(cve)
        info_field = CVE_TO_INFO_FIELD.get(cve)
        if not field:
            # 未在 20 列白名单中的 CVE，忽略或写日志
            continue
        defaults[field] = True if it.get("VULNERABLE") is True else False
        if info_field:
            defaults[info_field] = (it.get("INFOS") or "").strip()
    # 未给出的列保持 NULL（未知）
    DeviceVulnSnapshot.objects.update_or_create(mac=mac, defaults=defaults)
    
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
    row.pop("vulns", None)
    row.pop("vulnerabilities", None)
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
            # 1) 先处理 MachineReport（你已有的逻辑）
            row = _normalize_item(item)  # 会校验 REQUIRED_FIELDS 和解析 time
            lookup = {"mac": row["mac"], "time": row["time"]}
            defaults = {k: v for k, v in row.items() if k not in lookup}
            obj, created = MachineReport.objects.update_or_create(**lookup, defaults=defaults)
            created_count += int(created)
            updated_count += int(not created)

            # 2) 然后同步快照表（如果 payload 带了 20 项漏洞数组）
            # 兼容 key: "vulns" 或 "vulnerabilities"
            vulns = item.get("vulns") or item.get("vulnerabilities")
            if vulns is not None:
                upsert_vuln_snapshot(mac=row["mac"], vulns=vulns)

            results.append({"index": idx, "id": obj.id, "mac": obj.mac, "created": created})

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
    
    
FIELD_TO_CVE = {v: k for k, v in CVE_TO_FIELD.items()}

@api_view(["GET"])
def device_vuln_detail(request, mac: str):
    """返回某设备（mac）的 20 个 CVE 状态与 info"""
    obj = get_object_or_404(DeviceVulnSnapshot, pk=mac)

    # 收集所有 cve_* 布尔列与配套 *_info
    cve_rows = []
    for field_name, cve_id in FIELD_TO_CVE.items():
        affected = getattr(obj, field_name, False)
        info_field = f"{field_name}_info"
        info_text = getattr(obj, info_field, "")
        cve_rows.append({
            "cve": cve_id,           # 例如 "CVE-2017-5715"
            "affected": bool(affected),
            "info": info_text or "",
        })

    return Response({
        "mac": obj.mac,
        "cves": cve_rows,           # 前端直接渲染表格即可
        "updated_at": getattr(obj, "updated_at", None),
    })