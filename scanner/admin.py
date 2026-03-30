from django.contrib import admin
from django.utils.html import format_html

from .models import PaymentRecord, ScanResult, ScanTask, UserProfile


class ScanResultInline(admin.TabularInline):
    model = ScanResult
    extra = 0
    readonly_fields = ('port', 'state', 'service', 'reason', 'ttl', 'description')
    can_delete = False


@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    list_display = ('task_id', 'user', 'requested_target', 'target', 'scan_profile', 'risk_score', 'status', 'start_time', 'end_time', 'created_at')
    list_filter = ('status', 'scan_profile', 'start_time', 'end_time')
    search_fields = ('task_id', 'target', 'requested_target', 'user__username')
    readonly_fields = ('created_at', 'risk_score')
    ordering = ('-created_at',)
    inlines = [ScanResultInline]

    fieldsets = (
        ('Task Details', {
            'fields': ('user', 'task_id', 'requested_target', 'target', 'port_range', 'scan_profile', 'status', 'risk_score')
        }),
        ('Timestamps', {
            'fields': ('start_time', 'end_time', 'created_at')
        }),
    )


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'scan_count', 'has_paid', 'payment_status')
    list_filter = ('has_paid',)
    search_fields = ('user__username',)
    readonly_fields = ('payment_status',)

    def payment_status(self, obj):
        color = '#00ffc6' if obj.has_paid else '#ff4d4d'
        text = 'PAID' if obj.has_paid else 'FREE / NOT PAID'
        return format_html(f'<b style="color:{color}">{text}</b>')

    payment_status.short_description = 'Payment Status'


@admin.register(PaymentRecord)
class PaymentRecordAdmin(admin.ModelAdmin):
    list_display = ('user', 'razorpay_order_id', 'status', 'amount', 'created_at', 'colored_status')
    search_fields = ('user__username', 'razorpay_order_id', 'razorpay_payment_id')
    list_filter = ('status', 'created_at')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

    def colored_status(self, obj):
        color_map = {
            'PENDING': '#ffaa00',
            'SUCCESS': '#00ff7f',
            'FAILED': '#ff4d4d',
        }
        color = color_map.get(obj.status, '#ccc')
        return format_html(f'<b style="color:{color}">{obj.status}</b>')

    colored_status.short_description = 'Status (Colored)'

    fieldsets = (
        ('Payment Info', {
            'fields': ('user', 'amount', 'status', 'created_at')
        }),
        ('Razorpay Details', {
            'fields': ('razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature')
        }),
    )


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('scan', 'port', 'state', 'service', 'reason', 'ttl')
    list_filter = ('state',)
    search_fields = ('scan__target', 'service', 'reason')
    ordering = ('scan', 'port')
