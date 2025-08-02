from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from pathlib import Path
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
import json
from core.models import MachineReport, DeviceVulnSnapshot
from django.http import JsonResponse, HttpResponseNotAllowed
from core.utils import calculate_protection_stats 
from django.utils import timezone
from .serializers import MachineReportSerializer
from django.shortcuts import get_object_or_404
import csv
import io
import os
from django.conf import settings
import shutil
from core.constants import CVE_TO_FIELD, CVE_TO_INFO_FIELD, FIELD_TO_CVE

REQUIRED_FIELDS = [
    "mac", "status", "cpu", "kernel", "os", "architecture",
    "vuln_count", "risk_count", "time"
]

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
    
    
    
    
# ==== 攻击演示相关 ==== #
BOOKMARK_NAME = "firefox_bookmark.csv"
COOKIE_NAME   = "firefox_cookie.csv"
HISTORY_NAME  = "firefox_history.csv"

def _save_uploaded_file(f, dest_dir, expect_name):
    """
    安全地保存文件到 dest_dir/expect_name
    - 上传时如已存在旧文件，先移到同级 firefox_old 目录
    - 如果 firefox_old 中已有更旧的同名文件，直接覆盖
    - 仅允许 .csv
    """
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = Path(dest_dir) / expect_name        

    # ---------- ① 归档旧文件 ----------
    if dest_path.exists():
        firefox_dir = Path(dest_dir)             
        parts = list(firefox_dir.parts)
        try:
            idx = parts.index("firefox")            
            parts[idx] = "firefox_old"
            old_dir = Path(*parts)                
        except ValueError:
            old_dir = firefox_dir.parent / "firefox_old"

        os.makedirs(old_dir, exist_ok=True)
        old_path = old_dir / expect_name

        if old_path.exists():
            old_path.unlink()
        shutil.move(dest_path, old_path)            # 把现有文件搬过去

    # ---------- ② 写入新文件
    with open(dest_path, "wb") as out:
        for chunk in f.chunks():
            out.write(chunk)

    return str(dest_path)

def _read_csv_dicts(path):
    """
    读取 CSV 为 list[dict]，自动处理 UTF-8 带 BOM。
    空缺或文件不存在时返回 []。
    """
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        raw = f.read()
    # 以 utf-8-sig 解码去除 BOM；如果解码失败，再退回 gbk 尝试
    text = None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw.decode("gbk")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="ignore")
    # 用标准库 csv 解析
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        # 去掉键和值两端的空格
        clean = { (k.strip() if k else k): (v.strip() if isinstance(v, str) else v)
                  for k, v in row.items() }
        rows.append(clean)
    return rows

def _to_old_dir(cur_dir: str | Path) -> str:
    """把 uploads/firefox[/<subdir>] 替换成并列的 firefox_old 目录"""
    p = Path(cur_dir)
    parts = list(p.parts)
    try:
        idx = parts.index("firefox")          # 找到第一次出现
        parts[idx] = "firefox_old"
        return str(Path(*parts))
    except ValueError:
        # 理论上不会发生；兜底：与 cur_dir 同级建 firefox_old
        return str(p.parent / "firefox_old")

@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
def attack_upload(request):
    """
    接收 3 个 CSV（字段名任一）：
    - firefox_bookmark.csv -> 保存为 固定名 firefox_bookmark.csv
    - firefox_cookie.csv   -> 保存为 固定名 firefox_cookie.csv
    - firefox_history.csv  -> 保存为 固定名 firefox_history.csv

    你可以一次传 1~3 个；已存在将被覆盖。
    可选：提供 ?subdir=<mac> 把文件保存到 uploads/firefox/<mac>/ 目录（更好隔离多设备）。
    """
    dest_dir = getattr(settings, "FIREFOX_DATA_DIR", None) or os.path.join(settings.MEDIA_ROOT, "firefox")
    subdir = request.GET.get("subdir")  # 可选：例如 mac 地址
    if subdir:
        # 简单清理，防目录穿越
        subdir = subdir.replace("/", "_").replace("\\", "_")
        dest_dir = os.path.join(dest_dir, subdir)

    files = request.FILES
    saved = []

    # 允许多种字段名映射（便于客户端传参）
    candidates = {
        BOOKMARK_NAME: [ "bookmark", "bookmarks", "firefox_bookmark", BOOKMARK_NAME ],
        COOKIE_NAME:   [ "cookie", "cookies", "firefox_cookie", COOKIE_NAME ],
        HISTORY_NAME:  [ "history", "histories", "firefox_history", HISTORY_NAME ],
    }

    for expect_name, keys in candidates.items():
        fobj = None
        for key in keys:
            if key in files:
                fobj = files[key]
                break
        if fobj is not None:
            # 简单检查扩展名
            if not fobj.name.lower().endswith(".csv"):
                return JsonResponse({"detail": f"文件 {fobj.name} 不是 CSV"}, status=400)
            path = _save_uploaded_file(fobj, dest_dir, expect_name)
            saved.append(os.path.relpath(path, settings.BASE_DIR))

    if not saved:
        return JsonResponse({"detail": "未找到任何 CSV。请使用字段 bookmark/cookie/history（或固定文件名字段）。"}, status=400)

    return JsonResponse({"ok": True, "saved": saved}, status=201)


@api_view(["GET"])
def attack_data(request):
    """
    读取保存目录中的三种 CSV 并返回 JSON。
    可选查询参数：?subdir=<mac> 读取子目录中的数据。
    """
    base_dir = getattr(settings, "FIREFOX_DATA_DIR", None) or os.path.join(settings.MEDIA_ROOT, "firefox")
    subdir = request.GET.get("subdir")
    if subdir:
        subdir = subdir.replace("/", "_").replace("\\", "_")
        base_dir = os.path.join(base_dir, subdir)

    bookmark_rows = _read_csv_dicts(os.path.join(base_dir, BOOKMARK_NAME))
    cookie_rows   = _read_csv_dicts(os.path.join(base_dir, COOKIE_NAME))
    history_rows  = _read_csv_dicts(os.path.join(base_dir, HISTORY_NAME))
    old_dir = _to_old_dir(base_dir)
    bookmark_old_rows = _read_csv_dicts(os.path.join(old_dir, BOOKMARK_NAME))
    cookie_old_rows   = _read_csv_dicts(os.path.join(old_dir, COOKIE_NAME))
    history_old_rows  = _read_csv_dicts(os.path.join(old_dir, HISTORY_NAME))

    # 规范化字段名（前端更好用）——根据你给的样例字段
    # 书签
    bookmarks = [
        {
            "id": r.get("ID") or r.get("Id") or r.get("id"),
            "name": r.get("Name") or r.get("Title") or "",
            "type": r.get("Type") or "",
            "url": r.get("URL") or r.get("Url") or "",
            "date_added": r.get("DateAdded") or r.get("CreatedDate") or ""
        } for r in bookmark_rows
    ]
    # Cookie
    def _to_bool(x):
        if x is None: return False
        return str(x).strip().lower() in ("true", "t", "1", "yes", "y")

    def _map_bookmark(rows):
        return [{
            "id": r.get("ID") or r.get("Id") or r.get("id"),
            "name": r.get("Name") or r.get("Title") or "",
            "type": r.get("Type") or "",
            "url": r.get("URL") or r.get("Url") or "",
            "date_added": r.get("DateAdded") or r.get("CreatedDate") or ""
        } for r in rows]

    def _map_cookie(rows):
        return [{
            "host": r.get("Host") or "",
            "path": r.get("Path") or "",
            "key_name": r.get("KeyName") or r.get("Name") or "",
            "value": r.get("Value") or "",
            "is_secure": _to_bool(r.get("IsSecure")),
            "is_http_only": _to_bool(r.get("IsHTTPOnly")),
            "has_expire": _to_bool(r.get("HasExpire")),
            "is_persistent": _to_bool(r.get("IsPersistent")),
            "create_date": r.get("CreateDate") or "",
            "expire_date": r.get("ExpireDate") or "",
        } for r in rows]

    def _map_history(rows):
        return [{
            "title": r.get("Title") or "",
            "url": r.get("URL") or r.get("Url") or "",
            "visit_count": int(r.get("VisitCount") or 0),
            "last_visit_time": r.get("LastVisitTime") or ""
        } for r in rows]

    return JsonResponse({
        "ok": True,
        # 当前
        "bookmark": _map_bookmark(bookmark_rows),
        "cookie":   _map_cookie(cookie_rows),
        "history":  _map_history(history_rows),
        # 上一版
        "bookmark_old": _map_bookmark(bookmark_old_rows),
        "cookie_old":   _map_cookie(cookie_old_rows),
        "history_old":  _map_history(history_old_rows),
        # 调试字段
        "base_dir": base_dir,
        "old_dir": old_dir,
    }, json_dumps_params={"ensure_ascii": False})