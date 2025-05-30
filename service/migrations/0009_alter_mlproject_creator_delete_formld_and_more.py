# Generated by Django 5.1.6 on 2025-05-26 13:01

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0008_creatorprofile_mlproject'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mlproject',
            name='creator',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='projects', to='service.userprofile'),
        ),
        migrations.DeleteModel(
            name='formld',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='role',
            field=models.CharField(choices=[('general', 'General User'), ('creator', 'ML Project Creator'), ('admin', 'Administrator')], default='general', max_length=10),
        ),
        migrations.DeleteModel(
            name='CreatorProfile',
        ),
    ]
