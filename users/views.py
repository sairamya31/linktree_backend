from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from .models import User, Referral
from .serializers import UserSerializer, ReferralSerializer
from django.contrib.auth import authenticate, get_user_model
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import bcrypt
import logging
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
class RegisterView(APIView):
    def post(self, request):
        referral_code = request.data.get('referral_code')
        if referral_code:
            referrer = User.objects.filter(referral_code=referral_code).first()
            if not referrer:
                return Response({'error': 'Invalid referral code.'}, status=status.HTTP_400_BAD_REQUEST)
            request.data['referred_by'] = referrer.id
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user.referred_by:
                Referral.objects.create(referrer=user.referred_by, referred_user=user, status='pending')
                user.referred_by.reward_points += 10  # Add reward points for the referrer
                user.referred_by.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

User = get_user_model()

# Configure logging
logger = logging.getLogger(__name__)



class LoginView(APIView):
    def post(self, request):
        email_or_username = request.data.get("email_or_username")
        password = request.data.get("password")

        logger.info(f"Received login request for email/username: {email_or_username}")

        try:
            # Try fetching the user by email or username
            if "@" in email_or_username:
                user = User.objects.get(email=email_or_username)
            else:
                user = User.objects.get(username=email_or_username)
            logger.info(f"User found: {user.email}")
            logger.info(f"Stored Hashed Password: {user.password}")
        except User.DoesNotExist:
            logger.warning(f"Login failed for email/username: {email_or_username} (User does not exist)")
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # Verify the password
        if check_password(password, user.password):
            logger.info(f"Password match successful for email/username: {email_or_username}")

            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )
        else:
            logger.warning(f"Password mismatch for email/username: {email_or_username}")
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)



class ReferralListView(APIView):
    def get(self, request):
        referrals = Referral.objects.filter(referrer=request.user)
        serializer = ReferralSerializer(referrals, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ReferralStatsView(APIView):
    def get(self, request):
        total_referrals = Referral.objects.filter(referrer=request.user).count()
        successful_referrals = Referral.objects.filter(referrer=request.user, status='successful').count()
        return Response({
            'total_referrals': total_referrals,
            'successful_referrals': successful_referrals,
        }, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            )
            send_mail(
                'Password Reset',
                f'Click the link to reset your password: {reset_url}',
                'noreply@example.com',
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)