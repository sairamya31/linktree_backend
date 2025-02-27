from django.urls import path
from .views import RegisterView, LoginView, ReferralListView, ReferralStatsView, ForgotPasswordView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('referrals/', ReferralListView.as_view(), name='referrals'),
    path('referral-stats/', ReferralStatsView.as_view(), name='referral-stats'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
]