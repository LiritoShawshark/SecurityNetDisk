# Generated by Django 2.2 on 2020-07-04 12:18

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0006_auto_20200703_1144'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='upload_time',
            field=models.DateTimeField(default=datetime.datetime(2020, 7, 4, 12, 18, 56, 884837)),
        ),
    ]
