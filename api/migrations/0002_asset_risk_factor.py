# Generated by Django 3.2.8 on 2021-10-29 03:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='risk_factor',
            field=models.FloatField(default=0),
        ),
    ]
