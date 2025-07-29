from django.db import migrations
from datetime import datetime
from django.utils import timezone

mock_reports = [
    {
        'id': 1,
        'filename': 'machine_a_report.json',
        'status': '已分析',
        'cpu': 'Intel i5-12500H',
        'kernel': '6.8.0-60-generic',
        'os': 'Ubuntu 21.04',
        'architecture': 'x86_64',
        'vuln_count': 20,
        'risk_count': 2,
        'time': '2025-06-15 14:22:18'
    },
    {
        'id': 2,
        'filename': 'machine_a_report.json',
        'status': '已分析',
        'cpu': 'Intel i5-12500H',
        'kernel': '6.8.0-60-generic',
        'os': 'Ubuntu 23.04',
        'architecture': 'x86_64',
        'vuln_count': 20,
        'risk_count': 2,
        'time': '2025-06-15 14:22:18'
    },
    {
        'id': 3,
        'filename': 'machine_a_report.json',
        'status': '已分析',
        'cpu': 'Intel i5-12500H',
        'kernel': '6.8.0-60-generic',
        'os': 'Ubuntu 25.04',
        'architecture': 'x86_64',
        'vuln_count': 20,
        'risk_count': 2,
        'time': '2025-06-15 14:22:18'
    }
]



def load_initial_reports(apps, schema_editor):
    MachineReport = apps.get_model('core', 'MachineReport')

    for item in mock_reports:
        # 1. 复制一份，避免原数据被修改
        row = dict(item)

        # 2. 绝对不要把外部的 id 写入数据库，让自增主键接管
        row.pop('id', None)

        # 3. 处理时间：把 "YYYY-MM-DD HH:MM:SS" 转为**有时区**的 datetime
        dt = datetime.strptime(row['time'], "%Y-%m-%d %H:%M:%S")
        row['time'] = timezone.make_aware(dt, timezone.get_current_timezone())

        # 4. 幂等保护：若已存在同名且同时间的记录，就跳过（避免重复执行迁移时冲突）
        if MachineReport.objects.filter(filename=row['filename'], time=row['time']).exists():
            continue

        MachineReport.objects.create(**row)

class Migration(migrations.Migration):

    dependencies = [("core", "0001_initial")]
    operations   = [migrations.RunPython(load_initial_reports)]
