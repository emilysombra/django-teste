from django.urls import include, path
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^assets/$', views.AssetList.as_view(), name='asset-list'),
    url(r'^asset/(?P<pk>[0-9]+)/$', views.AssetDetail.as_view(), name='asset-detail'),
    url(r'^vulnerabilities/$', views.VulnerabilityList.as_view(), name='vulnerability-list'),
    url(r'^vulnerability/(?P<pk>[0-9]+)/$', views.VulnerabilityDetail.as_view(), name='vulnerability-detail'),
    url(r'^vulnerability_in_asset/(?P<pk>[0-9]+)/$', views.VulnerabilityInAssetDetail.as_view(), name='vulnerability_in_asset-detail'),
    url(r'^dashboard/assets/$', views.DashboardAssets.as_view(), name='dashboard-assets'),
    url(r'^dashboard/vulnerabilities/$', views.DashboardVulnerabilities.as_view(), name='dashboard-vulnerabilities'),
    url(r'^dashboard/vulnerabilities-in-assets/$', views.DashboardVulnerabilitiesInAssets.as_view(), name='dashboard-vulnerabilities-in-assets'),
    url(r'^dashboard/risk/$', views.DashboardRisk.as_view(), name='dashboard-risk'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('upload-csv/', views.upload_csv, name='upload_csv'),
]
