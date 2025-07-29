from rest_framework import serializers
from django.utils import timezone
from datetime import datetime
from core.models import MachineReport

class MachineSerializer(serializers.Serializer):
    id = serializers.CharField()
    mac = serializers.CharField()
    cpu = serializers.CharField()
    kernel = serializers.CharField()
    full_kernel = serializers.CharField()
    os = serializers.CharField()
    architecture = serializers.CharField()
    report_time = serializers.CharField()
    vuln_count = serializers.IntegerField()
    risk_count = serializers.IntegerField()

class CVEStatSerializer(serializers.Serializer):
    cve = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField()
    protected_count = serializers.IntegerField()
    protection_rate = serializers.FloatField()

class MachineReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = MachineReport
        fields = ["mac","status","cpu","kernel","os","architecture",
                  "vuln_count","risk_count","time"]
    def validate_time(self, value):
        # 若传来的是字符串，尝试解析；若为 naive datetime，加时区
        if isinstance(value, str):
            s = value.strip().replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(s)
            except Exception:
                dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
            if dt.tzinfo is None:
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            return dt
        if value.tzinfo is None:
            return timezone.make_aware(value, timezone.get_current_timezone())
        return value