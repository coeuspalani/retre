# Generated by Django 5.1.6 on 2025-05-30 05:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0014_rename_submitted_at_mlprojectfile_submitted_att'),
    ]

    operations = [
        migrations.RenameField(
            model_name='mlprojectfile',
            old_name='file',
            new_name='project_file',
        ),
    ]
