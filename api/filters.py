from django.db.models import query
import django_filters as filters
from django_filters.utils import label_for_filter

from .models import Asset, Vulnerability


class VulnerabilityFilter(filters.FilterSet):
    asset = filters.ModelChoiceFilter(queryset=Asset.objects.all(), method='filter_asset', label='Asset')
    class Meta:
        model = Vulnerability
        fields = ['title', 'cvss', 'severity', 'asset']
    
    def filter_asset(self, queryset, name, value):
        if value:
            vulnerabilities_id = value.vulnerabilities.values_list('id', flat=True)
            return queryset.filter(id__in=vulnerabilities_id)

        return queryset
