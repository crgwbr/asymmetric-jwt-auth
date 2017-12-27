# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('asymmetric_jwt_auth', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='publickey',
            name='comment',
            field=models.CharField(max_length=100, help_text='Comment describing this key', default=''),
            preserve_default=False,
        ),
    ]
