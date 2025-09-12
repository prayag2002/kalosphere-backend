from rest_framework import generics, permissions, APIView, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import RegisterSerializer
from .models import User

class RegisterView(generics.CreateAPIView):
    """
    API endpoint for user registration.
    - Accepts: email, username, password
    - Validates input with RegisterSerializer
    - Creates a new user account
    """

    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]  # anyone can register

    def create(self, request: Request, *args, **kwargs) -> Response:
        """
        Override to customize response format.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user: User = serializer.save()
        return Response(
            {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
            },
            status=HTTP_201_CREATED,
        )


class LogoutView(APIView):
    """
    API endpoint to log out a user.
    Blacklists their refresh token so it cannot be reused.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs) -> Response:
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"detail": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)