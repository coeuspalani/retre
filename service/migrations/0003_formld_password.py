# Generated by Django 5.1.6 on 2025-03-03 10:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0002_alter_formld_email_alter_formld_uname'),
    ]

    operations = [
        migrations.AddField(
            model_name='formld',
            name='password',
            field=models.CharField(default='<PASSWORD>', max_length=100),
        ),
    ]
