# Generated by Django 3.2.16 on 2023-03-08 20:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Notes', '0016_alter_note_deleted_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='note',
            name='deleted_at',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
    ]
