from django.db import models


class MachineReport(models.Model):
    mac           = models.CharField(max_length=64,db_index=True)
    status        = models.CharField(max_length=20)       
    cpu           = models.CharField(max_length=64)
    kernel        = models.CharField(max_length=128)
    os            = models.CharField(max_length=64)
    architecture  = models.CharField(max_length=32)
    vuln_count    = models.PositiveIntegerField()
    risk_count    = models.PositiveIntegerField()
    time          = models.DateTimeField()

    class Meta:
        db_table = "machine_report"
        ordering = ["id"]

    def __str__(self):
        return f"{self.id} – {self.mac}"
