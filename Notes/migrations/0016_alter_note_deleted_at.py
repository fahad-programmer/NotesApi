# Generated by Django 3.2.16 on 2023-03-08 20:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Notes', '0015_alter_note_deleted_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='note',
            name='deleted_at',
            field=models.DateField(blank=True, default='1-Jan-2023', null=True),
        ),
    ]