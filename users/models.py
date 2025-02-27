from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinLengthValidator
import uuid
from django.contrib.auth.hashers import make_password
class User(AbstractUser):
    email = models.EmailField(unique=True)
    referral_code = models.CharField(max_length=20, unique=True, null=True, blank=True)
    referred_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reward_points = models.IntegerField(default=0)  # Reward system for referrals

    # Add unique related_name for groups and user_permissions
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_name="custom_user_set",  # Unique related_name
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="custom_user_set",  # Unique related_name
        related_query_name="user",
    )

    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = str(uuid.uuid4())[:8]  # Generate referral code

        # ✅ Hash password only when creating a new user
        if self._state.adding and self.password and not self.password.startswith('pbkdf2_sha256$'):
            self.password = make_password(self.password)

        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

class Referral(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('successful', 'Successful'),
        ('failed', 'Failed'),
    ]

    referrer = models.ForeignKey(User, related_name='referrals', on_delete=models.CASCADE)
    referred_user = models.OneToOneField(User, related_name='referred_by_user', on_delete=models.CASCADE)
    date_referred = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return f"{self.referrer.username} referred {self.referred_user.username}"