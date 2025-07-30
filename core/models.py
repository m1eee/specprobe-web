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

class DeviceVulnSnapshot(models.Model):
    mac = models.CharField(max_length=64, primary_key=True)

    cve_2017_5753  = models.BooleanField(null=True)  # SPECTRE VARIANT 1
    cve_2017_5715  = models.BooleanField(null=True)  # SPECTRE VARIANT 2
    cve_2017_5754  = models.BooleanField(null=True)  # MELTDOWN
    cve_2018_3640  = models.BooleanField(null=True)  # VARIANT 3A
    cve_2018_3639  = models.BooleanField(null=True)  # VARIANT 4
    cve_2018_3615  = models.BooleanField(null=True)  # L1TF SGX
    cve_2018_3620  = models.BooleanField(null=True)  # L1TF OS
    cve_2018_3646  = models.BooleanField(null=True)  # L1TF VMM
    cve_2018_12126 = models.BooleanField(null=True)  # MSBDS
    cve_2018_12130 = models.BooleanField(null=True)  # MFBDS
    cve_2018_12127 = models.BooleanField(null=True)  # MLPDS
    cve_2019_11091 = models.BooleanField(null=True)  # MDSUM
    cve_2019_11135 = models.BooleanField(null=True)  # TAA
    cve_2018_12207 = models.BooleanField(null=True)  # ITLBMH
    cve_2020_0543  = models.BooleanField(null=True)  # SRBDS
    cve_2023_20593 = models.BooleanField(null=True)  # ZENBLEED
    cve_2022_40982 = models.BooleanField(null=True)  # DOWNFALL
    cve_2022_4543  = models.BooleanField(null=True) 
    cve_2023_20569 = models.BooleanField(null=True)  # INCEPTION
    cve_2023_23583 = models.BooleanField(null=True)  # REPTAR

    cve_2017_5753_info = models.TextField(blank=True, default="")
    cve_2017_5715_info  = models.TextField(blank=True, default="") # SPECTRE VARIANT 2
    cve_2017_5754_info  = models.TextField(blank=True, default="")  # MELTDOWN
    cve_2018_3640_info  = models.TextField(blank=True, default="") # VARIANT 3A
    cve_2018_3639_info  = models.TextField(blank=True, default="") # VARIANT 4
    cve_2018_3615_info  = models.TextField(blank=True, default="") # L1TF SGX
    cve_2018_3620_info  = models.TextField(blank=True, default="") # L1TF OS
    cve_2018_3646_info  = models.TextField(blank=True, default="") # L1TF VMM
    cve_2018_12126_info = models.TextField(blank=True, default="") # MSBDS
    cve_2018_12130_info = models.TextField(blank=True, default="") # MFBDS
    cve_2018_12127_info = models.TextField(blank=True, default="") # MLPDS
    cve_2019_11091_info = models.TextField(blank=True, default="") # MDSUM
    cve_2019_11135_info = models.TextField(blank=True, default="") # TAA
    cve_2018_12207_info = models.TextField(blank=True, default="") # ITLBMH
    cve_2020_0543_info  = models.TextField(blank=True, default="") # SRBDS
    cve_2023_20593_info = models.TextField(blank=True, default="") # ZENBLEED
    cve_2022_40982_info = models.TextField(blank=True, default="") # DOWNFALL
    cve_2022_4543_info  = models.TextField(blank=True, default="")
    cve_2023_20569_info = models.TextField(blank=True, default="") # INCEPTION
    cve_2023_23583_info = models.TextField(blank=True, default="") # REPTAR
    # 占位
    extra_1        = models.BooleanField(null=True)

    class Meta:
        db_table = "device_vuln_snapshot"

    def __str__(self):
        return self.mac