# Generated by Django 2.2 on 2020-07-03 11:44

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0005_auto_20200703_1142'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='f_pk',
            field=models.CharField(default='1', max_length=256),
        ),
        migrations.AlterField(
            model_name='file',
            name='upload_time',
            field=models.DateTimeField(default=datetime.datetime(2020, 7, 3, 11, 44, 8, 588787)),
        ),
    ]