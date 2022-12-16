import jwt
from django.contrib import messages
from django.contrib.auth.hashers import check_password, make_password
from django.db.models import Q
from django.db.utils import IntegrityError
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework.response import Response
from locations.models import Location
from django.shortcuts import redirect
# from locations.views import viewLoc

from .decorators import login_required
from .models import Tokenstable, User
from .serializers import AuthUserSerializer, TokenSerializer, UserSerializer
from .utils import send_passwordreset_email

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings

# Create your views here.


@api_view(['GET', 'POST'])
def login(request):
    if request.method == "POST":
        username = request.data.get('username')
        password = request.data.get('password')
        # print(username, password)
        if username is None or password is None:
            messages.error(
                request, "Empty Fields.Try again")
            return render(request, 'login.html')

        user = User.objects.filter(username=username).first()
        if user is None:
            messages.error(
                request, "User not found.")
            return render(request, 'login.html')

        instance = user
        user = AuthUserSerializer(user).data

        # checking password
        if check_password(password, user.get('password')) == False:
            messages.error(
                request, "Username or password is incorrect.")
            return render(request, 'login.html')

        # generating tokens
        access_token = instance.getAccessToken()
        refresh_token = instance.getRefreshToken()
        print('access_token => ', access_token)
        print('refresh_token => ', refresh_token)

        response = Response({
            'user': user,
            'access_token': access_token
        })
        response.set_cookie('jwt_refresh_token', refresh_token, httponly=True)
        # return render(request, 'index.html', {'locations': loc})
        return redirect("/api/location/")
    else:
        return render(request, 'login.html')


@api_view(['GET', 'POST'])
def register(request):
    if request.method == "POST":
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        if username is None or password is None or email is None:
            raise AuthenticationFailed(code=401)
        # IntegrityError
        try:
            instance = User(username=username, email=email)
            instance.password = make_password(password)
            instance.save()
        except IntegrityError:
            messages.warning(
                request, "Email or Username already exist ")
            return render(request, 'register.html')
        except:
            messages.error(
                request, "Some error occured please try again.")
            return render(request, 'register.html')

        user = UserSerializer(instance).data
        access_token = instance.getAccessToken()
        refresh_token = instance.getRefreshToken()
        print('access_token => ', access_token)
        print('refresh_token => ', refresh_token)
        response = Response({
            'user': user,
            'access_token': access_token
        })
        response.set_cookie('jwt_refresh_token', refresh_token, httponly=True)
        print(response)
        return render(request, 'login.html')
    else:
        return render(request, 'register.html')


@api_view(['GET'])
@login_required
def private(request):
    return Response({
        'message': 'private route hit'
    })


@api_view(['GET'])
def refresh(request):
    refresh_token = request.COOKIES.get('jwt_refresh_token')
    if refresh_token is None:
        return Response(status=403)
    user = User.objects.filter(refreshToken=refresh_token).first()

    if user is None:
        return Response(403)

    try:
        payload = jwt.decode(refresh_token, 'secret', algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return Response(status=403)
    except:
        return Response(status=500)

    seralized_user = UserSerializer(user).data

    if seralized_user.get('id') != payload.get('id'):
        return Response(status=403)

    access_token = user.getAccessToken()

    return Response({
        'access_token': access_token,
        'user': seralized_user
    })


# /api/auth/reset_password?userid=id&token=token
# validate the token and reset otherwise throw the error

@csrf_exempt
@api_view(['POST', 'GET'])
def reset_password(request, token, userId):
    if request.method == "POST":
        user = User.objects.filter(id=userId).first()
        claimedUser = Tokenstable.objects.filter(resetToken=token).first()

        if user is None:
            raise NotFound(code=404)

        if claimedUser is None:
            raise NotFound(code=400)

        serializedClaimedUser = TokenSerializer(claimedUser).data
        serializedUser = AuthUserSerializer(user).data
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 is None or password2 is None:
            messages.warning(
                request, "Fields are empty. Please enter your new Password")
            return render(request, 'reset_password.html', {"token": token, 'userId': userId})

        if serializedClaimedUser.get('userid') != userId:
            messages.error(
                request, "Unauthorized access.")
            return render(request, 'reset_password.html', {"token": token, 'userId': userId})

        try:
            payload = jwt.decode(token, serializedUser.get(
                'password'), algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            claimedUser.delete()
            return Response(status=401)
        except:
            return Response(status=500)

        # print(payload)

        if payload.get('id') != serializedUser.get('id'):
            messages.error(
                request, "Unauthorized access.")
            return render(request, 'reset_password.html', {"token": token, 'userId': userId})

        if password1 != password2:
            messages.error(
                request, "Password dont match.Try again")
            return render(request, 'reset_password.html', {"token": token, 'userId': userId})

        user.password = make_password(password1)
        user.save()
        claimedUser.delete()
        messages.success(
            request, "Password Changed successfully. Please login in.")
        return redirect('login')

    elif request.method == "GET":
        print(token)
        print(userId)
        return render(request, 'reset_password.html', {"token": token, 'userId': userId})
# payload = jwt.decode(refresh_token, 'secret', algorithms=["HS256"])
# /api/resetpassword


@ api_view(['GET', 'POST'])
def resetpasssord(request):
    if request.method == "POST":
        username = request.POST.get('username')
        print(username)

        user = User.objects.filter(Q(username=username)).first()
        if user is None:
            messages.error(
                request, "User not found.")
            return render(request, 'forgot-pass.html')

        serialized_user = UserSerializer(user).data
        reset_token = user.getPasswordRefreshToken()
        print(reset_token)
        token = Tokenstable(userid=user.id, resetToken=reset_token)
        try:
            tempToken = Tokenstable.objects.get(userid=user.id)
            print(tempToken)
            if tempToken is not None:
                messages.warning(
                    request, "Reset link has already been sent")
                return render(request, 'forgot-pass.html')
            else:
                token.save()
        except Exception as e:
            token.save()



        print(serialized_user.get('email'))

        context = {
            'link': str("http://localhost:8000/api/auth/reset/" + str(reset_token) + "/" + str(user.id) + "/"),
        }
        print(context)

        msg_plain = render_to_string('email.txt')
        msg_html = render_to_string('email.html', {'context': context})

        send_mail("Password reset request",
                  msg_plain,
                  settings.EMAIL_HOST_USER,
                  [serialized_user.get('email')],
                  html_message=msg_html,
                  )

        # send_passwordreset_email(
        #     serialized_user.get('email'), reset_token, user.id)

        messages.success(
            request, "Reset link has been sent to your registered email.")
        return render(request, 'forgot-pass.html')
    else:
        return render(request, 'forgot-pass.html')


@ api_view(["GET"])
def test(request, testNo):
    print(testNo)
    return Response(status=400)

# seperete this view
# expected route - /api/logout not /api/auth/logout


@ api_view(['GET'])
def logout(request):
    refresh_token = request.COOKIES.get('jwt_refresh_token')
    print(refresh_token)
    if refresh_token is None:
        return Response(status=204)

    user = User.objects.filter(refreshToken=refresh_token).first()
    serialized_user = UserSerializer(user).data
    print(serialized_user)
    if user is None:
        response = Response(status=204)
        response.delete_cookie('jwt_refresh_token')
        return response

    user.refreshToken = ""
    user.save()
    serialized_user = UserSerializer(user).data

    print(serialized_user)
    response = Response(status=200)
    response.delete_cookie('jwt_refresh_token')

    return response
