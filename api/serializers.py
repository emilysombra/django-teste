from rest_framework import serializers
from .models import Vulnerability, Asset, VulnerabilityInAsset
from django.db.models import Max


class AssetSerializer(serializers.HyperlinkedModelSerializer):
    vulnerabilities_count = serializers.SerializerMethodField()
    class Meta:
        model = Asset
        fields = ('hostname', 'ip', 'vulnerabilities_count', 'risk_factor')
    
    def get_vulnerabilities_count(self, obj):
        return obj.vulnerabilities.count()


class VulnerabilitySerializer(serializers.HyperlinkedModelSerializer):
    assets_count = serializers.SerializerMethodField()
    class Meta:
        model = Vulnerability
        fields = ('title', 'severity', 'cvss', 'publication_date', 'assets_count')
    
    def get_assets_count(self, obj):
        return obj.asset_set.count()


class VulnerabilityInAssetSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = VulnerabilityInAsset
        fields = ('solved',)


class VulnerabilitiesInAssetDetailSerializer(serializers.HyperlinkedModelSerializer):
    corrected = serializers.SerializerMethodField()
    class Meta:
        model = Vulnerability
        fields = ('title', 'severity', 'cvss', 'corrected')
    
    def get_corrected(self, obj):
        return VulnerabilityInAssetSerializer(obj.vulnerabilityinasset_set.first()).data['solved']


class AssetDetailSerializer(serializers.HyperlinkedModelSerializer):
    vulnerabilities = serializers.SerializerMethodField()
    class Meta:
        model = Asset
        fields = ('hostname', 'ip', 'vulnerabilities')
    
    def get_vulnerabilities(self, obj):
        return VulnerabilitiesInAssetDetailSerializer(obj.vulnerabilities.all(), many=True).data
