# utils.py
from django.db.models import Q
from core.models import MachineReport, DeviceVulnSnapshot      # ☆ 记得导入
from core.constants import FIELD_TO_CVE

def calculate_protection_stats():
    # ① 机器清单
    reports_qs = MachineReport.objects.filter(status="已分析")
    machines   = [{
        "id"          : f"machine_{r.id}",
        "mac"         : r.mac,
        "name"        : r.mac,                      # 看实际字段
        "cpu"         : r.cpu,
        "kernel"      : r.kernel.split("-")[0],
        "full_kernel" : r.kernel,
        "os"          : r.os,
        "architecture": r.architecture,
        "report_time" : r.time.strftime("%Y-%m-%d %H:%M:%S"),
        "vuln_count"  : r.vuln_count,
        "risk_count"  : r.risk_count,
    } for r in reports_qs]

    total_machines = len(machines)
    if total_machines == 0:        # 没有数据时保持旧返回格式
        return {
            "machines": [],
            "vulnerabilities": [],
            "stats": {
                "total_cves"        : 0,
                "fully_protected"   : 0,
                "partially_protected": 0,
                "unprotected"       : 0,
                "total_machines"    : 0,
            }
        }

    # ② 快照表聚合
    mac_list   = [m["mac"] for m in machines]
    snapshots  = DeviceVulnSnapshot.objects.filter(mac__in=mac_list)

    cve_fields = [
        f.name for f in DeviceVulnSnapshot._meta.get_fields()
        if f.name.startswith("cve_") and not f.name.endswith("_info")
    ]

    vulnerabilities      = []
    fully_protected_cnt  = 0
    partially_protected_cnt = 0
    unprotected_cnt      = 0

    for field in cve_fields:
        protected = snapshots.filter(Q(**{field: False})).count()   # 已打补丁
        affected  = snapshots.filter(Q(**{field: True})).count()    # 仍受影响
        unknown   = total_machines - protected - affected

        if protected == total_machines:
            fully_protected_cnt += 1
            tag = "fully_protected"
        elif protected == 0:
            unprotected_cnt     += 1
            tag = "unprotected"
        else:
            partially_protected_cnt += 1
            tag = "partially_protected"

        vulnerabilities.append({
            "cve"            : FIELD_TO_CVE.get(field, field.upper()),
            "protected_count": protected,
            "affected_count" : affected,
            "unknown_count"  : unknown,
            "status"         : tag,
        })

    return {
        "machines": machines,
        "vulnerabilities": vulnerabilities,
        "stats": {
            "total_cves"        : len(cve_fields),
            "fully_protected"   : fully_protected_cnt,
            "partially_protected": partially_protected_cnt,
            "unprotected"       : unprotected_cnt,
            "total_machines"    : total_machines,
        }
    }
