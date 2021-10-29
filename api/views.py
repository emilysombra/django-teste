from django.http import JsonResponse
from rest_framework import generics
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from django_filters import rest_framework as filters
from rest_framework.permissions import IsAuthenticated
from .serializers import AssetSerializer, VulnerabilitySerializer, AssetDetailSerializer, VulnerabilityInAssetSerializer
from .models import Asset, Vulnerability, VulnerabilityInAsset
import pandas as pd
from datetime import datetime
from .filters import VulnerabilityFilter
from django.db.models import Count, Q, Avg


# Create your views here.
class VulnerabilityList(generics.ListCreateAPIView):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = (IsAuthenticated, )
    filter_backends = (filters.DjangoFilterBackend,)
    filter_class = VulnerabilityFilter


class VulnerabilityDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = (IsAuthenticated, )
    filter_backends = (filters.DjangoFilterBackend,)
    filter_fields = '__all__'


class AssetList(generics.ListCreateAPIView):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = (IsAuthenticated, )
    filter_backends = (filters.DjangoFilterBackend,)
    filter_fields = '__all__'


class AssetDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Asset.objects.all()
    serializer_class = AssetDetailSerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = (IsAuthenticated, )
    filter_backends = (filters.DjangoFilterBackend,)
    filter_fields = '__all__'


class VulnerabilityInAssetDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = VulnerabilityInAsset.objects.all()
    serializer_class = VulnerabilityInAssetSerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = (IsAuthenticated, )
    filter_backends = (filters.DjangoFilterBackend,)
    filter_fields = '__all__'


class DashboardAssets(APIView):
    def get(self, request, format=None, **kwargs):
        vulnerable_hosts = VulnerabilityInAsset.objects.filter(solved=False).distinct('asset_id').values_list('asset_id', flat=True)
        return Response({
            'num_hosts': Asset.objects.count(),
            'vulnerable_hosts': Asset.objects.filter(id__in=vulnerable_hosts).count()
        })


class DashboardVulnerabilities(APIView):
    def get(self, request, format=None, **kwargs):
        return Response({
            'num_vulnerabilities': Vulnerability.objects.count(),
            'unsolved_vulnerabilities': VulnerabilityInAsset.objects.filter(solved=False).distinct('vulnerability_id').count()
        })


class DashboardVulnerabilitiesInAssets(APIView):
    def get(self, request, format=None, **kwargs):
        vulnerabilities = VulnerabilityInAsset.objects.filter(solved=False).distinct('vulnerability_id').values_list('vulnerability_id', flat=True)
        severities = Vulnerability.objects.filter(id__in=vulnerabilities).aggregate(
            low=Count('id', filter=Q(severity='Baixo')),
            medium=Count('id', filter=Q(severity='Médio')),
            high=Count('id', Q(severity='Alto')),
            critical=Count('id', severity='Crítico'))
        return Response({
            'unsolved_vulnerabilities_by_severity': dict(severities),
            'most_vulnerable_hosts': VulnerabilityInAsset.objects.filter(solved=False).values('asset').annotate(Count('vulnerability')).order_by('-vulnerability__count')[:10]
        })


class DashboardRisk(APIView):
    def get(self, request, format=None, **kwargs):
        return Response({
            'risk_factor': Asset.objects.aggregate(Avg('risk_factor')).get('risk_factor__avg', 0.0)
        })


def upload_csv(request):
    df = pd.read_csv('asset_vulnerability.csv').to_dict('records')
    for x in df:
        if isinstance(x['VULNERABILITY - PUBLICATION_DATE'], str):
            x_date = datetime.strptime(x['VULNERABILITY - PUBLICATION_DATE'], '%Y-%m-%d')
        else:
            x_date = None

        new_vulnerability = None
        try:
            new_vulnerability = Vulnerability.objects.get(title=x['VULNERABILITY - TITLE'])
        except Vulnerability.DoesNotExist:
            new_vulnerability = Vulnerability.objects.create(
                title = x['VULNERABILITY - TITLE'],
                severity = x['VULNERABILITY - SEVERITY'],
                cvss = x['VULNERABILITY - CVSS'],
                publication_date = x_date
            )
        except Vulnerability.MultipleObjectsReturned:
            new_vulnerability = Vulnerability.objects.filter(title=x['VULNERABILITY - TITLE']).first()

        new_asset, created = Asset.objects.get_or_create(
            hostname = x['ASSET - HOSTNAME'],
            ip = x['ASSET - IP_ADDRESS'],
        )

        if new_asset.risk_factor < new_vulnerability.cvss:
            new_asset.risk_factor = new_vulnerability.cvss
            new_asset.save()

        new_asset.vulnerabilities.add(new_vulnerability)

    return JsonResponse({'status': 'sucesso'})
