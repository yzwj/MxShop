# Generated by Django 2.0 on 2018-04-10 08:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cases', '0002_auto_20170926_1752'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='case',
            options={'ordering': ['-created_on']},
        ),
    ]
