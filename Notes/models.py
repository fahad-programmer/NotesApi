from django.db import models
# Create your models here.
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver


class Note(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200, blank=True)
    body = models.TextField()
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    deleted_at = models.DateField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def trash(self):
        self.is_deleted = True
        self.deleted_at = timezone.now().date()  # set deleted_at to current date
        delete_old_notes(sender=Note, instance=self)
        self.save()

    def restore(self):
        self.is_deleted = False
        self.deleted_at = None
        self.save()

    def __str__(self):
        return self.title


@receiver(post_save, sender=Note)
def delete_old_notes(sender, **kwargs):
    days_to_keep = 7
    oldest_allowed_date = timezone.now() - timezone.timedelta(days=days_to_keep)
    old_notes = Note.objects.filter(deleted_at__lt=oldest_allowed_date)
    for note in old_notes:
        note.delete()


class UserActions(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=1000, blank=False, default="", null=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.user.username


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    reset_password_pin = models.CharField(max_length=6, blank=True, null=True)
    number_of_notes = models.IntegerField(default=0, blank=True, null=True)