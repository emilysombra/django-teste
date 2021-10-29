from django.db import models

# Create your models here.

class Vulnerability(models.Model):
    class Meta:
        db_table = 'vulnerabilities'
    title = models.TextField()
    severity = models.CharField(max_length=10)
    cvss = models.FloatField(default=None, blank=True, null=True)
    publication_date = models.DateField(default=None, blank=True, null=True)

    def __str__(self):
        return self.title


class Asset(models.Model):
    class Meta:
        db_table = 'assets'
    hostname = models.CharField(max_length=60)
    ip = models.CharField(max_length=15)
    vulnerabilities = models.ManyToManyField(Vulnerability, through='VulnerabilityInAsset')
    risk_factor = models.FloatField(default=0)

    def __str__(self):
        return self.hostname


class VulnerabilityInAsset(models.Model):
    class Meta:
        db_table = 'vulnerabilities_in_assets'
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    solved = models.BooleanField(default=False)
