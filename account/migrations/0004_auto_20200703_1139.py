# Generated by Django 2.2 on 2020-07-03 11:39

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0003_auto_20200701_1434'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='f_pk',
            field=models.CharField(default=None, max_length=256),
        ),
        migrations.AlterField(
            model_name='file',
            name='sort',
            field=models.CharField(default=None, max_length=256),
        ),
        migrations.AlterField(
            model_name='file',
            name='upload_time',
            field=models.DateTimeField(default=datetime.datetime(2020, 7, 3, 11, 39, 50, 425786)),
        ),
    ]