# Generated by Django 4.1.1 on 2022-11-14 19:04

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("tickets", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Payment",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("payment_request_id", models.CharField(max_length=150)),
                ("payment_id", models.CharField(max_length=150)),
                ("response", models.TextField(max_length=1000)),
                (
                    "ticket",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="tickets.ticket"
                    ),
                ),
            ],
        ),
    ]