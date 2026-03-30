from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    scan_count = models.PositiveIntegerField(default=0)
    has_paid = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


class PaymentRecord(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    razorpay_order_id = models.CharField(max_length=255, unique=True)
    razorpay_payment_id = models.CharField(max_length=255, blank=True, null=True)
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=49.00)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.razorpay_order_id} - {self.status}"


class ScanTask(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scan_tasks', null=True, blank=True)
    task_id = models.CharField(max_length=255, unique=True)
    requested_target = models.CharField(max_length=255, blank=True)
    target = models.CharField(max_length=255)
    port_range = models.CharField(max_length=50, default='1-1024')
    scan_profile = models.CharField(max_length=50, default='custom')
    risk_score = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.target} ({self.task_id}) - {self.status}"


class ScanResult(models.Model):
    scan = models.ForeignKey('ScanTask', on_delete=models.CASCADE)
    port = models.IntegerField()
    state = models.CharField(max_length=20)
    service = models.CharField(max_length=100, blank=True)
    reason = models.CharField(max_length=50, blank=True)
    ttl = models.CharField(max_length=10, blank=True)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.scan.target}:{self.port} {self.state}"
