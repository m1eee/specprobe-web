from .models import MachineReport


def calculate_protection_stats():
    # ① 读库
    reports = MachineReport.objects.filter(status="已分析")
    # ② 生成机器 列表
    machines = []
    for idx, r in enumerate(reports, start=1):
        machine_name = r.mac
        machines.append({
            "id": f"machine_{r.id}",
            "mac":   r.mac,
            "name":       machine_name,
            "cpu":        r.cpu,
            "kernel":     r.kernel.split('-')[0],
            "full_kernel":r.kernel,
            "os":         r.os,
            "architecture": r.architecture,
            "report_time":  r.time.strftime("%Y-%m-%d %H:%M:%S"),
            "vuln_count":   r.vuln_count,
            "risk_count":   r.risk_count,
        })
    
    vulnerabilities = []
    
    # 计算统计信息
    total_machines = len(machines)
    fully_protected = sum(1 for v in vulnerabilities if v['protected_count'] == total_machines)
    partially_protected = sum(1 for v in vulnerabilities if 0 < v['protected_count'] < total_machines)
    unprotected = sum(1 for v in vulnerabilities if v['protected_count'] == 0)
    
    return {
        'machines': machines,
        'vulnerabilities': vulnerabilities,
        'stats': {
            'total_cves': len(vulnerabilities),
            'fully_protected': fully_protected,
            'partially_protected': partially_protected,
            'unprotected': unprotected,
            'total_machines': total_machines
        }
    }