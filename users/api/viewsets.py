import os
import random
import uuid
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.files.storage import default_storage
from rest_framework import viewsets, permissions, status, pagination
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import FileUploadParser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from users.models import Profile

from .serializers import UserProfileSerializer, UserSerializer, UserSerializerWithToken

User = get_user_model()


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        # Add extra responses here
        data['token_expiry'] = refresh.access_token.lifetime
        data['refresh_expiry'] = refresh.lifetime
        data['email'] = self.user.email
        data['name'] = self.user.profile.name
        data['profile_pic'] = self.user.profile.profile_pic.url
        return data

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        data = request.data
        email = data.get('email')
        name = data.get('name')
        password = data.get('password')
        messages = {'errors':[]}
        if email == None:
            messages['errors'].append('Email can\'t be empty')
        if password == None:
            messages['errors'].append('Password can\'t be empty')
        if User.objects.filter(email=email).exists():
            messages['errors'].append("Account already exists with this email id.")    
        if User.objects.filter(email__iexact=email).exists():
            messages['errors'].append("Account already exists with this username.") 
        if len(messages['errors']) > 0:
            return Response({"detail":messages['errors']},status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.create(
                email=email,
                password=make_password(password)
            )

            profile = Profile.objects.create(
                user = user,
                name = name,
            )
            serializer = UserSerializerWithToken(user, context={'request': request},many=False)
        except Exception as e:
            print(e)
            return Response({'detail':f'{e}'},status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.data)

class UserProfileUpdate(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer
    #http_method_names = ['patch', 'head']


    def patch(self, *args, **kwargs):
        profile = self.request.user.profile
        serializer = self.serializer_class(
            profile, data=self.request.data, partial=True)
        if serializer.is_valid():
            user = serializer.save().user
            new_name = self.request.data.get('name')
            user = self.request.user
            if new_name is not None:
                profile.name = new_name
                profile.save()
            return Response({'success': True, 'message': 'successfully updated your info',
                        'user': UserSerializer(user).data,'updated_name': new_name}, status=200)
        else:
            response = serializer.errors
            return Response(response, status=401)


class ProfilePictureUpdate(APIView):
    permission_classes=[IsAuthenticated]
    serializer_class=UserProfileSerializer
    parser_class=(FileUploadParser,)

    def patch(self, *args, **kwargs):
        rd = random.Random()
        profile_pic=self.request.FILES['profile_pic']
        extension = os.path.splitext(profile_pic.name)[1]
        profile_pic.name='{}{}'.format(uuid.UUID(int=rd.getrandbits(128)), extension)
        filename = default_storage.save(profile_pic.name, profile_pic)
        setattr(self.request.user.userprofile, 'profile_pic', filename)
        serializer=self.serializer_class(
            self.request.user.userprofile, data={}, partial=True)
        if serializer.is_valid():
            user=serializer.save().user
            response={'type': 'Success', 'message': 'successfully updated your info',
                        'user': UserSerializer(user).data}
        else:
            response=serializer.errors
        return Response(response)

@api_view(['POST'])
@permission_classes((IsAuthenticated,))
def password_change(request):
    user = request.user
    data = request.data
    new_password = data.get('new_password')
    new_password_confirm = data.get('new_password_confirm')
    if new_password_confirm and new_password is not None:
        if new_password == new_password_confirm:
            user.set_password(new_password)
            user.save()
            return Response({'detail':'Password changed successfully'},status=status.HTTP_200_OK)
        else:
            return Response({"detail":'Password doesn\'t match'})
    elif new_password is None:
        return Response({'detail':'New password field required'})
    elif new_password_confirm is None:
        return Response({'detail':'New password confirm field required'})@api_view(['GET'])
