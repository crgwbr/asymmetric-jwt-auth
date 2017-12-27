# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('asymmetric_jwt_auth', '0002_publickey_comment'),
    ]

    operations = [
        migrations.AlterField(
            model_name='publickey',
            name='comment',
            field=models.CharField(blank=True, max_length=100, help_text='Comment describing this key'),
        ),
    ]
