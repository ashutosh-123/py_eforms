import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, inch, landscape
from rest_framework.permissions import AllowAny
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from rest_framework.decorators import api_view, permission_classes
from .models import *
from operator import itemgetter, attrgetter
from rest_framework import parsers, renderers
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from django.contrib.auth.hashers import check_password, make_password
from .serializers import *
from .exceptions import Exception
from rest_framework.response import Response
from django.db import transaction
from rest_framework import status
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from os import urandom
from base64 import b64encode
from django.shortcuts import render
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import redirect, render
from django.db import *
import socket
import datetime
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import permissions
from rest_framework import exceptions
from collections import OrderedDict
import json
import dropbox
from string import ascii_letters
from django.conf import settings
from django.core.urlresolvers import reverse
import requests
import os, random, md5
from django.db.models import Q
from rest_framework.views import APIView
from .tasks import *
from paypalrestsdk import Payment
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from rest_framework.pagination import PageNumberPagination

PAGE_SIZE = 10

class IsAPIKey(permissions.BasePermission):

    def has_permission(self, request, view):
        if request.META.get('HTTP_SECRETKEY', None):
            token_generator = PasswordResetTokenGenerator()
            token = request.META.get('HTTP_SECRETKEY')
            is_valid = token_generator.check_token(request.user, token)
            if is_valid == True:
                return True
            else:
                raise exceptions.PermissionDenied(detail='Inavlid Secret Key')

        raise exceptions.PermissionDenied(detail='Please send a SECRETKEY header or Secret Key can not be blank')


@api_view(['POST'])
#@permission_classes((permissions.AllowAny,))
@transaction.atomic
def register(request):

    user_data = request.data
    profile_img = user_data.get('profile_img', None)
    domain_pro = (get_current_site(request).domain)[:-1]
    if profile_img == None:
        profile_img = "profile_default.jpg"
        profile_img_url = domain_pro + "/media/profile_default.jpg"
    if user_data['email']:
        try:
            email = user_data['email'].split('@')[1]
        except IndexError:
            raise Exception('Please enter a valid User email i.e. example@domain.com')
        try:
            socket.gethostbyname(email)
        except(socket.gaierror):
            raise Exception('Please enter a valid domain for User Email')
    if user_data['is_organisation'] == 'True':
        user_data['role_type'] = 'OA'
        if user_data['organisation_email']:
            try:
                organisation_email_domain = user_data['organisation_email'].split('@')[1]
            except IndexError:
                raise Exception('Please enter a valid Organisation email i.e. example@domain.com')
            try:
                socket.gethostbyname(organisation_email_domain)
            except(socket.gaierror):
                raise Exception('Please enter a valid domain for Organisation Email')
            if Organisation.objects.filter(organisation_email__contains=organisation_email_domain).exists():
                raise Exception('Organisation email Domain is alredy registered')
        try:
                organisation = Organisation.objects.create(organistation_name=user_data['organisation_name'],
                                                       organisation_type=user_data['organisation_type'],
                                                       organisation_location=user_data['organisation_location'],
                                                       no_of_employees=user_data['no_of_employees'],
                                                       organisation_email=user_data['organisation_email'])
        except(IntegrityError):

            raise Exception('Either you are entering a already existing organisation email id or you are not sending an organisation email it is required')
    else:
        organisation = None
    try:
        user = CustomUser.objects.create(first_name=user_data['first_name'],
                                         last_name=user_data['last_name'],
                                         username=user_data['email'],
                                         email=user_data['email'],
                                         organisation=organisation,
                                         role_type=user_data['role_type'],
                                         profile_img=profile_img,
                                         passcode=user_data.get('passcode', None))
        if user.profile_img:
            profile_img_url = domain_pro + user.profile_img.url
            user.profile_url = profile_img_url
        else:
            user.profile_url = profile_img_url

    except(IntegrityError):

        raise Exception('either Your username or email is already existing')

    user.is_active = False
    user.password = make_password(user_data['password'])
    user.save()
    decoded_token = urandom(32)
    encoded_token = b64encode(decoded_token)
    encoded_token = encoded_token.split('=')[0]
    expiration_time = datetime.datetime.strftime(datetime.datetime.now() + datetime.timedelta(days=2), '%Y-%m-%d %H:%M:%S')
    EmailVerificationToken.objects.create(user=user, token=encoded_token, expiration_time=expiration_time)
    link = (get_current_site(request).domain)[:-1] + "/api/v1/auth/activate/{}".format(encoded_token)
    subject = 'Activate Your Eforms Account'
    message = 'Please verify your email by opening this link {}'.format(link)
    user_email = user_data['email']
    recipient_list = [user_email]
    from_email = ''
    try:
        send_mail(subject, message, from_email, recipient_list)
    except:
        raise Exception('please enter a valid email so that i can sent u a verification email')
    user_token = Token.objects.get(user_id=user)
    serializer = TokenSerializer(user_token)
    return Response(serializer.data)

@api_view(['GET'])
#@permission_classes((permissions.AllowAny,))
def activate(request, token):
        if EmailVerificationToken.objects.filter(token=token).exists():
            token_ob = EmailVerificationToken.objects.get(token=token)
            token_expiration_time = token_ob.expiration_time
            current_time = datetime.datetime.now()
            time_diff = token_expiration_time - current_time
            if time_diff.days == 0:
                return Response({'error': 'Your Token Has Been Expired'})
            user = token_ob.user
            user.is_active = True
            user.save()
            token_ob.delete()
            is_verified = True
            return redirect('http://50.116.5.169:8004/verified/')
        else:
            is_verified = False
            return redirect('http://50.116.5.169:8004/unverified/')

@api_view(['GET'])
def login(request):
    user = request.user
    print user
    is_app_login = request.query_params.get('is_app_login', None)
    print is_app_login
    if user.is_paid_user:
        user.is_trial_on = False
    if user.is_trial_on:
        if user.trial_expiry_date_time:
            remaining_trial_time = user.trial_expiry_date_time - datetime.datetime.now()
        else:
            remaining_trial_time = None
        if remaining_trial_time:
            user.remaining_trial_time = remaining_trial_time.days * 86400 + remaining_trial_time.seconds
        else:
            user.is_paid_user = False
        # if not remaining_trial_time:
        #     return Response({'message': 'Sorry, You are no longer able to LogIn because your trial period has been '
        #                                 'expired'})

    if not user.is_active:
        print "inactive user"
        raise Exception('Please verify your email first')
    token_generator = PasswordResetTokenGenerator()
    token = token_generator.make_token(request.user)
    if len(WelcomeModuleAdmin.objects.all()):
        pass
    else:
        WelcomeModuleAdmin.objects.create(message_activated=True,
                                          message='This is Dummy Welcome Module',
                                          video_activated=True,
                                          video='https://youtube/5lRFNP68eC8?list=PLFC3FA3400155E14A',
                                          module_price=300,
                                          is_enabled=True)
    if len(SubmitModuleAdmin.objects.all()):
        pass
    else:
        SubmitModuleAdmin.objects.create(is_enabled=True,
                                          message='This is Dummy Submit Module',
                                          module_price=300)

    if len(UnlockModuleAdmin.objects.all()):
        pass
    else:
        UnlockModuleAdmin.objects.create(is_enabled=True,
                                          message='This is Dummy Unlock Module',
                                          module_price=300)
    if len(GoogleDriveModuleAdmin.objects.all()):
        pass
    else:
        GoogleDriveModuleAdmin.objects.create(is_enabled=True,
                                          module_price=300)

    if len(EmailModuleAdmin.objects.all()):
        pass
    else:
        EmailModuleAdmin.objects.create(is_enabled=True,
                                              module_price=300)

    if len(DropboxModuleAdmin.objects.all()):
        pass
    else:
        DropboxModuleAdmin.objects.create(is_enabled=True,
                                          module_price=300)
    if request.user.role_type == 'A' or request.user.role_type == 'S':
        if AdminFormModules.objects.filter(is_default=True).exists():
            pass
        else:

            AdminFormModules.objects.create(title='Default',
                                            description='This is Deafult Form',
                                            module_price=500,
                                            min=5,
                                            max=5,
                                            created_by=request.user,
                                            user=request.user,
                                            is_default=True)
    if is_app_login:
        if user.role_type == 'OE' or user.role_type == 'C':
            print "logged in"
            user_data = UserSerializer(request.user, context={'API-KEY': token, 'request': request})
            data = user_data.data
            if remaining_trial_time:
                data['remaining_trial_time'] = str(user.remaining_trial_time / 86400) + " " + "Days" + " " + str(
                    (user.remaining_trial_time % 86400) / 3600) + " " + "Hours" + " "\
                                               + str(((user.remaining_trial_time % 86400) % 3600) / 60) + " " + "Minutes"
        else:
            raise Exception(' Login Not Allowed for You ')
    else:
        user_data = UserSerializer(request.user, context={'API-KEY': token, 'request': request})
        data = user_data.data
        if remaining_trial_time:
            data['remaining_trial_time'] = str(user.remaining_trial_time / 86400) + " " + "Days" + " " + str(
                (user.remaining_trial_time % 86400) / 3600) + " " + "Hours" + " "  \
                                           + str(((user.remaining_trial_time % 86400) % 3600) / 60) + " " + "Minutes"
    return Response(data)

@api_view(['GET'])
def delete_user(request):

    user_id = request.query_params.get('user_id', None)
    try:
        user_ob = CustomUser.objects.get(id=user_id)
        user_ob.is_deleted = True
        user_ob.is_active = False
        user_ob.save()
        return Response({'message': 'Successfully deleted'})
    except(CustomUser.DoesNotExist):
        raise Exception('User Does Not Exist or You are looking for an Anonymous User')

@api_view(['POST'])
def update_user(request):

    user_data = request.data
    if user_data['is_organisation'] == 'True':
        if user_data['organisation_id']:
            organisation = user_data['organisation_id']
            Organisation.objects.filter(id=user_data['organisation_id']).update(
                organistation_name=user_data['organisation_name'], organisation_type=user_data['organisation_type'],
                organisation_location=user_data['organisation_location'], no_of_employees=user_data['no_of_employees'],
                organisation_email=user_data['organisation_email'])
        else:
            organisation = Organisation.objects.create(organistation_name=user_data['organisation_name'], organisation_type=user_data['organisation_type'],
                                                       organisation_location=user_data['organisation_location'], no_of_employees=user_data['no_of_employees']
                                                       ,organisation_email=user_data['organisation_email'])
    else:
        if user_data['role_type'] == 'OE':
            organisation = Organisation.objects.get(organisation_email__contains=user_data['email'].split('@')[1])
        organisation = None

    user_id = user_data['user_id']
    is_active = user_data['is_active']
    if is_active == 1:
        is_active = True
    if is_active == 0:
        is_active = False
    user = CustomUser.objects.get(id=user_id)
    profile_img = user_data.get('profile_img', user.profile_img)
    if user_data['email']:
        try:
            email = user_data['email'].split('@')[1]
        except IndexError:
            raise Exception('Please enter a valid User email i.e. example@domain.com')
        try:
            socket.gethostbyname(email)
        except(socket.gaierror):
            raise Exception('Please enter a valid domain for User Email')
        CustomUser.objects.filter(id=user_id).update(first_name=user_data['first_name'], last_name=user_data['last_name'],
                                                     username=user_data['email'],
                                                 email=user_data['email'],
                                                 organisation=organisation, role_type=user_data['role_type'],
                                                 profile_img=profile_img,
                                                     passcode=user_data['passcode'],
                                                     is_active=is_active)
    try:
        user = CustomUser.objects.get(id=user_id)
        serializer = UserSerializer(user, context={'request': request})
        return Response(serializer.data)
    except(CustomUser.DoesNotExist):
        raise CustomUser.DoesNotExist('User Does Not Exist')

@api_view(['POST'])
def change_user_password(request):

    user_data = request.data
    try:
        user = CustomUser.objects.get(id=user_data['user_id'])
        if user_data['old_password']:
            if check_password(user_data['old_password'], user.password):
                user.password = make_password(user_data['new_password'])
                user.save()
                return Response({'message': 'Password Updated Successfully'}, status=status.HTTP_202_ACCEPTED)
            else:
                raise Exception('Your old password is incorrect')
        else:
            user.password = make_password(user_data['new_password'])
            user.save()
            return Response({'message': 'Password Updated Successfully'}, status=status.HTTP_202_ACCEPTED)

    except(CustomUser.DoesNotExist):
        raise CustomUser.DoesNotExist('User Does Not Exist')

@api_view(['GET'])
@permission_classes((AllowAny, ))
def forget_password(request):
        user_email = request.query_params.get('email', None)
        try:
            user = CustomUser.objects.get(email=user_email)
        except(CustomUser.DoesNotExist):
            raise Exception('Please send registered email id')
        if user_email:
            decoded_token = urandom(32)
            encoded_token = b64encode(decoded_token)
            ForgetPasswordToken.objects.create(user=user, token=encoded_token)
            link = (get_current_site(request).domain)[:-1] + "api/v1/reset_password/{0}/".format(encoded_token)
            subject = 'Reset Your Eforms Account Password'
            message = 'Please reset your password by opening this link {}'.format(link)
            recipient_list = [user_email]
            from_email = ''
            send_mail(subject, message, from_email, recipient_list)
            return Response({
                                'message': 'We have emailed you instructions for setting your password, if an account exists with the email you entered. You should receive them shortly.If you do not receive an email, please make sure you havve entered the address you registered with, and check your spam folder.'})

        else:
           raise Exception('Please provide an existing email id')

def reset_password(request, token):

    form = SetPasswordForm(None)
    if request.method == 'POST':
        if ForgetPasswordToken.objects.filter(token=token).exists():
            data = request.POST.dict()
            token_ob = ForgetPasswordToken.objects.get(token=token)
            form = SetPasswordForm(token_ob.user, data)
            if form.is_valid():
                form.save()
                token_ob.delete()
                return render(request, 'confirm.html', {'form': form})
            else:
                form = SetPasswordForm(None)
                return render(request, 'password_reset_confirm.html', {'form': form})
        else:
            return Response({'message': 'Your token has expired'})
    return render(request, 'password_reset_confirm.html', {'form': form})

@api_view(['GET'])
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def view_all_users(request):

    role_type = request.query_params.get('role_type', None)
    if role_type:
        if role_type == 'C':
            users = CustomUser.objects.filter(role_type__in=['C', 'OA'])
        else:
            users = CustomUser.objects.filter(role_type=role_type)
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

        # paginator = PageNumberPagination()
        # paginator.page_size = PAGE_SIZE
        # paginated_data = paginator.paginate_queryset(users, request)
        # serializer = UserSerializer(paginated_data, many=True)
        # return paginator.get_paginated_response(serializer.data)
    else:
        raise Exception('role_type is missing please send a role type to determine what type of users u want to get')

@api_view(['GET'])
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def view_user_profile(request):

    user_id = request.query_params.get('user_id', None)

    if user_id:
        try:
            user = CustomUser.objects.get(id=user_id)
            serializer = UserSerializer(user, context={'request': request})
            return Response(serializer.data)

        except(CustomUser.DoesNotExist):
            raise CustomUser.DoesNotExist('User Does not exist')
    else:
        raise Exception('User ID is missing in parameters')

@api_view(['POST'])
@transaction.atomic
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def add_user(request):

    user_data = request.data
    profile_img = user_data.get('profile_img', None)
    domain_pro = (get_current_site(request).domain)[:-1]
    if profile_img == 'null':
        profile_img = "profile_default.jpg"
        profile_img_url = domain_pro + "/media/profile_default.jpg"
    if user_data['is_organisation'] == 'True':
        try:
            organisation = Organisation.objects.create(organistation_name=user_data['organisation_name'], organisation_type=user_data['organisation_type'],
                                organisation_location=user_data['organisation_location'], no_of_employees=user_data['no_of_employees'],
                                                   organisation_email=user_data['organisation_email'])
        except IntegrityError:
            raise Exception('Your Organisation email is alredy existing')
    else:
        organisation = None
    if user_data:
        if user_data['email']:
            try:
                username = user_data['email'].split('@')[1]
            except IndexError:
                raise Exception('Please enter a valid User email i.e. example@domain.com')
            try:
                socket.gethostbyname(username)
            except(socket.gaierror):
                raise Exception('Please enter a valid domain for User Email')
        try:
            user = CustomUser.objects.create(first_name=user_data['first_name'], last_name=user_data['last_name'],
                                             username=user_data['email'], email=user_data['email'],
                                             organisation=organisation, role_type=user_data['role_type'],
                                             profile_img=profile_img,
                                            is_active=True)

        except IntegrityError:
            raise Exception('either your username or email is alredy existing')
        user.password = make_password(user_data['password'])
        user.save()
        serializer = UserSerializer(user, context={'request': request})
        return Response(serializer.data)
    else:
        raise Exception('No User Data')

@api_view(['POST'])
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def add_organisation_user(request):

    user_data = request.data
    profile_img = user_data.get('profile_img', None)
    domain_pro = (get_current_site(request).domain)[:-1]
    if profile_img == 'null':
        profile_img = "profile_default.jpg"
        profile_img_url = domain_pro + "/media/profile_default.jpg"
    if user_data:
        if user_data['email']:
            try:
                username = user_data['email'].split('@')[1]
            except IndexError:
                raise Exception('Please enter a valid User email i.e. example@domain.com')
            try:
                socket.gethostbyname(username)
            except(socket.gaierror):
                raise Exception('Please enter a valid domain for User Email')
        organisation = Organisation.objects.filter(organisation_email__contains=username)
        if organisation:

            try:
                user = CustomUser.objects.create(first_name=user_data['first_name'],
                                                 last_name=user_data['last_name'], username=user_data['email'],
                                                 email=user_data['email'], organisation=organisation[0],
                                                 role_type='OE',
                                                 profile_img=profile_img)
                user.set_password(user_data['password'])
                user.save()
                serializer = UserSerializer(user, context={'request': request})
                return Response(serializer.data)
            except IntegrityError:
                raise Exception()
        else:
           raise Exception('You are not from this Organisation or this is not a registered Organisation')

@api_view(['GET'])
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def view_organisation_users(request):

    organisation_id = request.query_params.get('organisation_id', None)
    is_active = int(request.query_params.get('is_active', None))
    if is_active == 1:
        is_active = True
        is_deleted = False
    else:
        is_active = False
        is_deleted = False
    if organisation_id:
        try:
            organisation_email_domain = Organisation.objects.get(id=organisation_id).organisation_email.split('@')[1]
            organisation_users = CustomUser.objects.filter(email__contains=organisation_email_domain, role_type='OE',\
                                 organisation__isnull=False, is_active=is_active, is_deleted=is_deleted)
            if organisation_users:

                serializer = UserSerializer(organisation_users, many=True)
                return Response(serializer.data)

                # paginator = PageNumberPagination()
                # paginator.page_size = PAGE_SIZE
                # paginated_data = paginator.paginate_queryset(organisation_users, request)
                # serializer = UserSerializer(paginated_data, many=True)
                # return paginator.get_paginated_response(serializer.data)
            else:
                return Response({'message': 'No Users For this Organisation'})
        except(Organisation.DoesNotExist):
            raise Organisation.DoesNotExist('This Organisation Does not exist')
    else:
        raise Exception('Organisation ID is missing')


@api_view(['POST'])
@transaction.atomic
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def create_form(request):

    form_data = request.data
    if form_data:
        form_title = form_data['title']
        form_description = form_data['description']
        module_price = form_data['module_price']
        user = request.user
        form_d = json.loads(form_data['form'])
        #form_d = form_data['form']
        conditions = form_data.get('form_conditions', None)
        if conditions:
            form_conditions = json.loads(conditions)
        else:
            form_conditions = conditions
        if user.is_active:
            form = AdminFormModules.objects.create(title=form_title, description=form_description,
                                                   user=user,
                                                   module_price=module_price,
                                                   created_by=user.username,
                                                   min=form_data.get('min', None),
                                                   max=form_data.get('max',None)
                                                   )
            if form_conditions:
                for item in form_conditions:
                    Conditions.objects.create(if_field=item.get('if_field', None),
                                              state=item.get('state', None),
                                              condition=item.get('condition', None),
                                              field=item.get('field', None),
                                              value=item.get('value', None),
                                              form=form)
            for index, item in enumerate(form_d):
                insert_form_data(item=item, form=form, customer_template=None, index=index+1)

            return Response({'message': 'Successfully submitted formdata', 'form_id': form.id})

        raise Exception('You are an inactive user please verify Your email first')
    else:
        raise Exception('Form data is not available')
@transaction.atomic
def insert_form_data(item=None, form=None, customer_template=None, index=None):

    if item['element'] == 'Header':
        HeaderField.objects.create(
                                       form=form,
                                       label=item.get('text', None),
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', False),
                                       placeholder=item.get('content', None),
                                       step=index,
            customer_template=customer_template
                                )
        return

    if item['element'] == 'Label':
        LabelField.objects.create(
                                       label=item.get('text', None),
                                       form=form,
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', False),
                                       placeholder=item.get('content', None),
                                       step=index,
            customer_template=customer_template
        )
        return

    if item['element'] == 'LineBreak':
        LineBreakField.objects.create(
                                       label=item.get('text', None),
                                       form=form,
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', False),
                                       step=index,
            customer_template=customer_template
        )
        return

    if item['element'] == 'Checkboxes':

        singlecheckbox = SingleCheckBox.objects.create(
                                                       label=item.get('label', None),
                                                       form=form,
                                                       help_text=item.get('text', None),
                                                       name=item.get('field_name', None),
                                                       field_id=item.get('id', None),
                                                       is_required=item.get('required', False),
                                                       group=item.get('group', False),
                                                       canHaveAnswer=item.get('canHaveAnswer', False),
                                                       step=index,
            customer_template=customer_template

        )

        if singlecheckbox:
            for option in item['options']:
                Options.objects.create(
                                       option_label=option.get('label', None),
                                       option_value=option.get('value', None),
                                       option_field_id=option.get('key', None),
                                       selected=option.get('selected', False),
                                       option_text=option.get('text', None),
                                       singlecheckbox=singlecheckbox
                                       )
        return

    if item['element'] == 'Paragraph':
        ParagraphField.objects.create(
                                        label=item.get('label', None),
                                        form=form,
                                        help_text=item.get('text', None),
                                        name=item.get('field_name', None),
                                        field_id=item.get('id', None),
                                        is_required=item.get('required', False),
                                        bold=item.get('bold', False),
                                        italic=item.get('italic', False),
                                        static=item.get('static', False),
                                        group=item.get('group', False),
                                        step=index,
            customer_template=customer_template

        )
        return

    if item['element'] == 'Signature':
        SignatureField.objects.create(
                                            label=item.get('label', None),
                                            form=form,
                                            help_text=item.get('text', None),
                                            name=item.get('field_name', None),
                                            field_id=item.get('id', None),
                                            is_required=item.get('required', False),
                                            group=item.get('group', False),
                                            step=index,
            customer_template=customer_template

        )
        return

    if item['element'] == 'RadioButtons':
        singleradiobox = SingleRadioBox.objects.create(
                                                       label=item.get('label', None),
                                                       form=form,
                                                       help_text=item.get('text', None),
                                                       name=item.get('field_name', None),
                                                       field_id=item.get('id', None),
                                                       is_required=item.get('required', False),
                                                       group=item.get('group', False),
                                                       canHaveAnswer=item.get('canHaveAnswer', False),
                                                       step=index,
            customer_template=customer_template

        )
        if singleradiobox:
            for option in item['options']:
                Options.objects.create(
                                       option_label=option.get('label', None),
                                       option_value=option.get('value', None),
                                       option_text=option.get('text', None),
                                       option_field_id=option.get('key', None),
                                       selected=option.get('selected', False),
                                       singleradiobox=singleradiobox
                                       )
        return

    if item['element'] == 'TextInput':

        TextField.objects.create(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                                 step=index,
            customer_template=customer_template
        )
        return

    if item['element'] == 'NumberInput':

        NumberInput.objects.create(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                                 step=index,
            customer_template=customer_template
        )
        return

    if item['element'] == 'TextArea':

        TextArea.objects.create(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                                 step=index,
            customer_template=customer_template
        )
        return

    if item['element'] == 'Range':

        RangeField.objects.create(
                                 label=item.get('label', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 min_label=item.get('min_label', None),
                                 max_label=item.get('max_label', None),
                                 step=index,
                                 stepno=item.get('stepno', None),
                                 default_value=item.get('default_value', None),
                                 min_value=item.get('min_value', None),
                                 max_value=item.get('max_value', None),
                                 group=item.get('group', False),
            customer_template=customer_template

        )
        return

    if item['element'] == 'Camera':

        Camera.objects.create(
            label=item.get('text', None),
            form=form,
            help_text=item.get('text', None),
            name=item.get('field_name', None),
            field_id=item.get('id', None),
            is_required=item.get('required', False),
            group=item.get('group', False),
            step=index,
            customer_template=customer_template

        )
        return

    if item['element'] == 'Rating':

        RatingField.objects.create(
                                 label=item.get('label', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                                 step=index,
            customer_template=customer_template

        )
        return

    if item['element'] == 'Image':

        ImageField.objects.create(
                                 label=item.get('text', None),
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 src=item.get('src', None),
                                 form=form,
                                 step=index,
            center=item.get('center', None),
            customer_template=customer_template

        )
        return

    if item['element'] == 'ImageMarker':

        ImageOverlay.objects.create(
                                 label=item.get('label', None),
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 form=form,
                                 step=index,
            customer_template=customer_template

        )
        return


    if item['element'] == 'DatePicker':
        DateTimeField.objects.create(
                                     label=item.get('label', None),
                                     form=form,
                                     help_text=item.get('text', None),
                                     name=item.get('field_name', None),
                                     field_id=item.get('id', None),
                                     is_required=item.get('required', False),
                                     group=item.get('group', False),
                                     defaulttoday=item.get('defaultToday', False),
                                     readonly=item.get('readOnly', False),
                                     step=index,
            customer_template=customer_template

        )

        return

    if item['element'] == 'Dropdown':
        dropdown = DropDown.objects.create(
                                           label=item.get('label', None),
                                           form=form,
                                           help_text=item.get('text', None),
                                           name=item.get('field_name', None),
                                           field_id=item.get('id', None),
                                           is_required=item.get('required', False),
                                           group=item.get('group', False),
                                           canHaveAnswer=item.get('canHaveAnswer', False),
                                           step=index,
            customer_template=customer_template

        )
        if dropdown:
            for option in item['options']:
                Options.objects.create(
                                       option_text=option.get('text', None),
                                       option_value=option.get('value', None),
                                       option_field_id=option.get('key', None),
                                       option_label=option.get('label', None),
                                       selected=option.get('selected', False),
                                       dropdown=dropdown
                )

        return

    if item['element'] == 'Tags':
        tags = Tags.objects.create(
                                           label=item.get('label', None),
                                           form=form,
                                           help_text=item.get('text', None),
                                           name=item.get('field_name', None),
                                           field_id=item.get('id', None),
                                           is_required=item.get('required', False),
                                           group=item.get('group', False),
                                           canHaveAnswer=item.get('canHaveAnswer', False),
                                           step=index,
            customer_template=customer_template
        )
        if tags:
            for option in item['options']:
                print option
                Options.objects.create(
                                       option_text=option.get('text', None),
                                       option_value=option.get('value', None),
                                       option_field_id=option.get('key', None),
                                       option_label=option.get('label', None),
                                       selected=option.get('selected', False),
                                       tags=tags,

                )

        return


@api_view(['GET'])
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def get_terms_and_conditions(request):

    #TermsAndConditions.objects.create(content='These are My terms and conditions')
    tnc_ob = TermsAndConditions.objects.all().first()
    serializer = TermsAndConditionsSerializer(tnc_ob)
    return Response(serializer.data)


@api_view(['GET'])
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def get_privacy_policy(request):

    privacy_ob = PrivacyPolicy.objects.all().first()
    serializer = PrivacyPolicySerializer(privacy_ob)
    return Response(serializer.data)


@api_view(['GET'])
#@permission_classes((IsAPIKey, permissions.IsAuthenticated,))
def get_disclaimer(request):

    disclaim_ob = Disclaimer.objects.all().first()
    serializer = DisclaimerSerializer(disclaim_ob)
    return Response(serializer.data)

@api_view(['POST'])
@transaction.atomic
def update_customer_forms(request):

    form_data = request.data
    status = request.query_params.get('status', None)
    # form_d = json.loads(form_data)
    # form_data = form_d
    if form_data:
        form_id = form_data['customer_form_id']
        form_title = form_data['title']

        form_description = form_data['description']
        form_price = 0
        customer_form_data = json.loads(form_data['form'])
        deleted_templates = form_data['deleted_templates']
        functional = form_data.get('functional_modules', None)
        user = request.user
        if user.is_active:
            kwargs = {}
            form_ob = CustomerForms.objects.filter(id=form_id)
            if functional:
                func_modules = json.loads(functional)
                functional_modules = func_modules
                all_welcome_modules_in_this_form = WelcomeModuleCustomer.objects.filter(customer_form=form_ob[0])
                all_submit_modules_in_this_form = SubmitModuleCustomer.objects.filter(customer_form=form_ob[0])
                all_unlock_modules_in_this_form = UnlockModuleCustomer.objects.filter(customer_form=form_ob[0])
                all_dropbox_modules_in_this_form = DropboxModuleCustomer.objects.filter(customer_form=form_ob[0])
                all_drive_modules_in_this_form = GoogleDriveModuleCustomer.objects.filter(customer_form=form_ob[0])
                all_email_modules_in_this_form = EmailModuleCustomer.objects.filter(customer_form=form_ob[0])
                for module in functional_modules:
                    module_type = module.get('type')
                    module_data = module.get('data', None)[0]
                    module_id = module.get('cfm_id', None) or module.get('id', None)
                    if module_type == 'welcomemodule':
                        obj, created = WelcomeModuleCustomer.objects.update_or_create(id=module_id,
                                                                                      defaults=dict(
                                                                                                    message=module_data.get('message', None),
                                                                                                    video=module_data.get('video', None),
                                                                                                    image=module_data.get('image', None),
                                                                                                    logo=module_data.get('logo', None),
                                                                                                    customer_form=form_ob[0],
                                                                                                    user=user,
                                                                                          orderno=module_data.get(
                                                                                              'orderno', None),
                                                                                                    module_price=module_data.get('module_price', None)
                                                                                      )
                                                                                      )
                        if created:
                            all_welcome_modules_in_this_form.delete()

                    if module_type == 'submitmodule':
                        obj, created = SubmitModuleCustomer.objects.update_or_create(id=module_id,
                                                                      defaults=dict(
                                                                                    user=user,
                                                                                    customer_form=form_ob[0],
                                                                                    message=module_data.get('message', None),
                                                                                    module_price=module_data.get(
                                                                                        'module_price', None),
                                                                          orderno=module_data.get('orderno', None)

                                                                      )
                                                                      )
                        if created:
                            all_submit_modules_in_this_form.delete()

                    if module_type == 'unlockmodule':
                        obj, created = UnlockModuleCustomer.objects.update_or_create(id=module_id,
                                                                                     defaults=dict(
                                                                                                     user=user,
                                                                                                     customer_form=form_ob[0],
                                                                                                     message=module_data.get('message', None),
                                                                                                     module_price=module_data.get('module_price', None),
                                                                                         orderno=module_data.get(
                                                                                             'orderno', None)
                                                                                     )
                                                            )
                        if created:
                            all_unlock_modules_in_this_form.delete()

                    if module_type == 'dropboxmodule':
                        obj, created = DropboxModuleCustomer.objects.update_or_create(id=module_id,
                                                                                      defaults=dict(
                                                                                                    user=user,
                                                                                                    customer_form=form_ob[0],
                                                                                                    module_price=module_data.get('module_price', None),
                                                                                          orderno=module_data.get(
                                                                                              'orderno', None)
                                                                                      )
                                                             )
                        if created:
                            all_dropbox_modules_in_this_form.delete()

                    if module_type == 'emailmodule':
                        obj, created = EmailModuleCustomer.objects.update_or_create(id=module_id,
                                                                                      defaults=dict(
                                                                                                    user=user,
                                                                                                    customer_form=form_ob[0],
                                                                                                    module_price=module_data.get('module_price', None),
                                                                                          orderno=module_data.get(
                                                                                              'orderno', None)
                                                                                      )
                                                             )
                        if created:
                            all_email_modules_in_this_form.delete()

                    if module_type == 'drivemodule':
                        obj, created = GoogleDriveModuleCustomer.objects.update_or_create(id=module_id,
                                                                                          defaults=dict(
                                                                                                        user=user,
                                                                                                        customer_form=form_ob[0],
                                                                                                        module_price=module_data.get( 'module_price', None),
                                                                                              orderno=module_data.get(
                                                                                                  'orderno', None)
                                                                                          )
                                                                 )
                        if created:
                            all_drive_modules_in_this_form.delete()
            CustomerTemplates.objects.filter(customer_form=form_ob[0], id__in=deleted_templates).delete()
            for item in customer_form_data:
                title = item.get('title', None)
                description = item.get('description', None)
                template_id = item.get('customertemplate_id', None)
                module_price = item.get('module_price', None)
                min = item.get('min', None)
                max = item.get('max', None)
                template_form_data = item.get('form', None)
                orderno = item.get('orderno', None)
                conditions = item.get('conditions', None)
                if conditions:
                    form_conditions = conditions
                else:
                    form_conditions = None
                if template_id:
                    template_obs = CustomerTemplates.objects.filter(customer_form=form_ob[0], id=template_id)
                    template = template_obs[0]
                    template_obs.update(title=title,
                                        description=description,
                                        min=min,
                                        max=max,
                                        orderno=orderno
                                        )
                    form_price += template.module_price
                    if form_conditions:
                        for condition in form_conditions:
                            Conditions.objects.filter(customer_template=template).update(if_field=condition.get('if_field'),
                                                                                         state=condition.get('state'),
                                                                                         condition=condition.get('condition'),
                                                                                         field=condition.get('field'),
                                                                                         value=condition.get('value'),
                                                                                         )
                    all_headers_in_this_template = HeaderField.objects.filter(customer_template=template)
                    all_image_overlay_in_this_template = ImageOverlay.objects.filter(customer_template=template)
                    all_checkboxes_in_this_template = SingleCheckBox.objects.filter(customer_template=template)
                    all_labels_in_this_template = LabelField.objects.filter(customer_template=template)
                    all_paragraphs_in_this_template = ParagraphField.objects.filter(customer_template=template)
                    all_signatures_in_this_template = SignatureField.objects.filter(customer_template=template)
                    all_radiobuttons_in_this_template = SingleRadioBox.objects.filter(customer_template=template)
                    all_textfields_in_this_template = TextField.objects.filter(customer_template=template)
                    all_datepickers_in_this_template = DateTimeField.objects.filter(customer_template=template)
                    all_dropdowns_in_this_template = DropDown.objects.filter(customer_template=template)
                    all_linebreaks_in_this_template = LineBreakField.objects.filter(customer_template=template)
                    all_numbers_in_this_template = NumberInput.objects.filter(customer_template=template)
                    all_textareas_in_this_template = TextArea.objects.filter(customer_template=template)
                    all_ranges_in_this_template = RangeField.objects.filter(customer_template=template)
                    all_cameras_in_this_template = Camera.objects.filter(customer_template=template)
                    all_ratings_in_this_template = RatingField.objects.filter(customer_template=template)
                    all_images_in_this_template = ImageField.objects.filter(customer_template=template)
                    all_tags_in_this_template = Tags.objects.filter(customer_template=template)
                    previous_field_ids = []
                    all_fields_ids = []
                    all_option_field_ids = []
                    updated_options = []
                    all_option_in_dropdown = Options.objects.filter(dropdown__in=all_dropdowns_in_this_template). \
                        values_list('option_field_id', flat=True)
                    all_option_in_checkboxes = Options.objects.filter(singlecheckbox__in=all_checkboxes_in_this_template). \
                        values_list('option_field_id', flat=True)
                    all_option_in_tags = Options.objects.filter(tags__in=all_tags_in_this_template). \
                        values_list('option_field_id', flat=True)
                    all_option_in_radiobuttons = Options.objects.filter(singleradiobox__in=all_radiobuttons_in_this_template). \
                        values_list('option_field_id', flat=True)
                    all_option_field_ids.extend(all_option_in_checkboxes)
                    all_option_field_ids.extend(all_option_in_dropdown)
                    all_option_field_ids.extend(all_option_in_radiobuttons)
                    all_option_field_ids.extend(all_option_in_tags)
                    for header in all_headers_in_this_template:
                        all_fields_ids.append(header.field_id)

                    for image_overlay in all_image_overlay_in_this_template:
                        all_fields_ids.append(image_overlay.field_id)
                    for checkbox in all_checkboxes_in_this_template:
                        all_fields_ids.append(checkbox.field_id)
                    for label in all_labels_in_this_template:
                        all_fields_ids.append(label.field_id)
                    for paragraph in all_paragraphs_in_this_template:
                        all_fields_ids.append(paragraph.field_id)
                    for sign in all_signatures_in_this_template:
                        all_fields_ids.append(sign.field_id)
                    for radiobutton in all_radiobuttons_in_this_template:
                        all_fields_ids.append(radiobutton.field_id)
                    for text in all_textfields_in_this_template:
                        all_fields_ids.append(text.field_id)
                    for datepicker in all_datepickers_in_this_template:
                        all_fields_ids.append(datepicker.field_id)
                    for dropdown in all_dropdowns_in_this_template:
                        all_fields_ids.append(dropdown.field_id)
                    for linebreak in all_linebreaks_in_this_template:
                        all_fields_ids.append(linebreak.field_id)
                    for number in all_numbers_in_this_template:
                        all_fields_ids.append(number.field_id)
                    for textarea in all_textareas_in_this_template:
                        all_fields_ids.append(textarea.field_id)
                    for range in all_ranges_in_this_template:
                        all_fields_ids.append(range.field_id)
                    for camera in all_cameras_in_this_template:
                        all_fields_ids.append(camera.field_id)
                    for rating in all_ratings_in_this_template:
                        all_fields_ids.append(rating.field_id)
                    for image in all_images_in_this_template:
                        all_fields_ids.append(image.field_id)
                    for tag in all_tags_in_this_template:
                        all_fields_ids.append(tag.field_id)
                    kwargs['all_headers_in_this_form'] = all_headers_in_this_template
                    kwargs['all_image_overlay_in_this_form'] = all_image_overlay_in_this_template
                    kwargs['all_labels_in_this_form'] = all_labels_in_this_template
                    kwargs['all_linebreaks_in_this_form'] = all_linebreaks_in_this_template
                    kwargs['all_textareas_in_this_form'] = all_textareas_in_this_template
                    kwargs['all_numbers_in_this_form'] = all_numbers_in_this_template
                    kwargs['all_checkboxes_in_this_form'] = all_checkboxes_in_this_template
                    kwargs['all_paragraphs_in_this_form'] = all_paragraphs_in_this_template
                    kwargs['all_signatures_in_this_form'] = all_signatures_in_this_template
                    kwargs['all_radiobuttons_in_this_form'] = all_radiobuttons_in_this_template
                    kwargs['all_textfields_in_this_form'] = all_textfields_in_this_template
                    kwargs['all_datepickers_in_this_form'] = all_datepickers_in_this_template
                    kwargs['all_dropdowns_in_this_form'] = all_dropdowns_in_this_template
                    kwargs['all_ranges_in_this_form'] = all_ranges_in_this_template
                    kwargs['all_cameras_in_this_form'] = all_cameras_in_this_template
                    kwargs['all_ratings_in_this_form'] = all_ratings_in_this_template
                    kwargs['all_images_in_this_form'] = all_images_in_this_template
                    kwargs['all_tags_in_this_form'] = all_tags_in_this_template
                    for index, item in enumerate(template_form_data):
                        kwargs['item'] = item
                        kwargs['form'] = None
                        kwargs['customer_template'] = template
                        update_template(previous_field_ids, updated_options, index+1, **kwargs)
                    deleted_fields = list(set(all_fields_ids) - set(previous_field_ids))
                    all_headers_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_image_overlay_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_checkboxes_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_labels_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_paragraphs_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_signatures_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_radiobuttons_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_textfields_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_datepickers_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_dropdowns_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_linebreaks_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_numbers_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_textareas_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_ranges_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_cameras_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_ratings_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_images_in_this_template.filter(field_id__in=deleted_fields).delete()
                    all_tags_in_this_template.filter(field_id__in=deleted_fields).delete()

                    deleted_options = list(set(all_option_field_ids) - set(updated_options))
                    Options.objects.filter(option_field_id__in=deleted_options).delete()

                else:
                    print "ELSE"
                    template = CustomerTemplates.objects.create(title=title,
                                                                description=description,
                                                                module_price=module_price,
                                                                min=min,
                                                                max=max,
                                                                customer_form=form_ob[0],
                                                                orderno=orderno
                                                                )
                    #updated_template_ids.append(template.id)
                    print template
                    if form_conditions:
                        Conditions.objects.create(if_field=form_conditions.get('if_field'),
                                                  state=form_conditions.get('state'),
                                                  condition=form_conditions.get('condition'),
                                                  field=form_conditions.get('field'),
                                                  value=form_conditions.get('value'),
                                                  customer_template=template
                                                  )
                    template_id = item.get('admin_template_id', None)
                    template_ob = AdminFormModules.objects.get(id=template_id)
                    print template_ob
                    template_ob.customers.add(form_ob[0])
                    form_price += int(module_price)
                    for index, item in enumerate(template_form_data):
                        insert_form_data(item=item, form=None, customer_template=template, index=index + 1)
            form_ob.update(title=form_title,
                           description=form_description,
                           form_price=form_price,
                           status=status)
            return Response({'message': 'Successfully Updated formdata', "customer_id": request.user.id})

        raise Exception('You are an inactive user please verify your email first')
    else:
        raise Exception('Form Data is not available')

@api_view(['POST'])
@transaction.atomic
def update_admin_modules(request):

    form_data = request.data
    if form_data:
        form_id = form_data['form_id']
        form_title = form_data['title']
        form_description = form_data['description']
        module_price = form_data['module_price']
        conditions = form_data.get('form_conditions', None)
        if conditions:
            form_conditions = json.loads(conditions)
        else:
            form_conditions = None

        user = request.user
        if user.is_active:
            kwargs = {}
            form = AdminFormModules.objects.filter(id=form_id)
            form.update(title=form_title, description=form_description, user=user, module_price=module_price,
                        min=form_data.get('min', None),
                        max=form_data.get('max', None)
                        )
            form_ob = form[0]
            if form_conditions:
                Conditions.objects.filter(form=form_ob).update(if_field=form_conditions[0].get('if_field', None),
                                                               state=form_conditions[0].get('state', None),
                                                               condition=form_conditions[0].get('condition', None),
                                                               field=form_conditions[0].get('field', None),
                                                               value=form_conditions[0].get('value', None),
                                                               )
            all_headers_in_this_form = HeaderField.objects.filter(form=form_ob)
            all_checkboxes_in_this_form = SingleCheckBox.objects.filter(form=form_ob)
            all_labels_in_this_form = LabelField.objects.filter(form=form_ob)
            all_paragraphs_in_this_form = ParagraphField.objects.filter(form=form_ob)
            all_signatures_in_this_form = SignatureField.objects.filter(form=form_ob)
            all_radiobuttons_in_this_form = SingleRadioBox.objects.filter(form=form_ob)
            all_textfields_in_this_form = TextField.objects.filter(form=form_ob)
            all_datepickers_in_this_form = DateTimeField.objects.filter(form=form_ob)
            all_dropdowns_in_this_form = DropDown.objects.filter(form=form_ob)
            all_linebreaks_in_this_form = LineBreakField.objects.filter(form=form_ob)
            all_numbers_in_this_form = NumberInput.objects.filter(form=form_ob)
            all_textareas_in_this_form = TextArea.objects.filter(form=form_ob)
            all_ranges_in_this_form = RangeField.objects.filter(form=form_ob)
            all_cameras_in_this_form = Camera.objects.filter(form=form_ob)
            all_ratings_in_this_form = RatingField.objects.filter(form=form_ob)
            all_images_in_this_form = ImageField.objects.filter(form=form_ob)
            all_tags_in_this_form = Tags.objects.filter(form=form_ob)
            all_image_overlay_in_this_form = ImageOverlay.objects.filter(form=form_ob)
            previous_field_ids = []
            all_fields_ids = []
            all_option_field_ids = []
            updated_options = []
            all_option_in_dropdown = Options.objects.filter(dropdown__in=all_dropdowns_in_this_form).\
                values_list('option_field_id', flat=True)
            all_option_in_checkboxes = Options.objects.filter(singlecheckbox__in=all_checkboxes_in_this_form).\
                values_list('option_field_id', flat=True)
            all_option_in_tags = Options.objects.filter(tags__in=all_tags_in_this_form).\
                values_list('option_field_id', flat=True)
            all_option_in_radiobuttons = Options.objects.filter(singleradiobox__in=all_radiobuttons_in_this_form). \
                values_list('option_field_id', flat=True)
            all_option_field_ids.extend(all_option_in_checkboxes)
            all_option_field_ids.extend(all_option_in_dropdown)
            all_option_field_ids.extend(all_option_in_radiobuttons)
            all_option_field_ids.extend(all_option_in_tags)
            for header in all_headers_in_this_form:
                all_fields_ids.append(header.field_id)
            for image_overlay in all_image_overlay_in_this_form:
                all_fields_ids.append(image_overlay.field_id)
            for checkbox in all_checkboxes_in_this_form:
                all_fields_ids.append(checkbox.field_id)
            for label in all_labels_in_this_form:
                all_fields_ids.append(label.field_id)
            for paragraph in all_paragraphs_in_this_form:
                all_fields_ids.append(paragraph.field_id)
            for sign in all_signatures_in_this_form:
                all_fields_ids.append(sign.field_id)
            for radiobutton in all_radiobuttons_in_this_form:
                all_fields_ids.append(radiobutton.field_id)
            for text in all_textfields_in_this_form:
                all_fields_ids.append(text.field_id)
            for datepicker in all_datepickers_in_this_form:
                all_fields_ids.append(datepicker.field_id)
            for dropdown in all_dropdowns_in_this_form:
                all_fields_ids.append(dropdown.field_id)
            for linebreak in all_linebreaks_in_this_form:
                all_fields_ids.append(linebreak.field_id)
            for number in all_numbers_in_this_form:
                all_fields_ids.append(number.field_id)
            for textarea in all_textareas_in_this_form:
                all_fields_ids.append(textarea.field_id)
            for range in all_ranges_in_this_form:
                all_fields_ids.append(range.field_id)
            for camera in all_cameras_in_this_form:
                all_fields_ids.append(camera.field_id)
            for rating in all_ratings_in_this_form:
                all_fields_ids.append(rating.field_id)
            for image in all_images_in_this_form:
                all_fields_ids.append(image.field_id)
            for tag in all_tags_in_this_form:
                all_fields_ids.append(tag.field_id)
            kwargs['all_headers_in_this_form'] = all_headers_in_this_form
            kwargs['all_image_overlay_in_this_form'] = all_image_overlay_in_this_form
            kwargs['all_labels_in_this_form'] = all_labels_in_this_form
            kwargs['all_linebreaks_in_this_form'] = all_linebreaks_in_this_form
            kwargs['all_textareas_in_this_form'] = all_textareas_in_this_form
            kwargs['all_numbers_in_this_form'] = all_numbers_in_this_form
            kwargs['all_checkboxes_in_this_form'] = all_checkboxes_in_this_form
            kwargs['all_paragraphs_in_this_form'] = all_paragraphs_in_this_form
            kwargs['all_signatures_in_this_form'] = all_signatures_in_this_form
            kwargs['all_radiobuttons_in_this_form'] = all_radiobuttons_in_this_form
            kwargs['all_textfields_in_this_form'] = all_textfields_in_this_form
            kwargs['all_datepickers_in_this_form'] = all_datepickers_in_this_form
            kwargs['all_dropdowns_in_this_form'] = all_dropdowns_in_this_form
            kwargs['all_ranges_in_this_form'] = all_ranges_in_this_form
            kwargs['all_cameras_in_this_form'] = all_cameras_in_this_form
            kwargs['all_ratings_in_this_form'] = all_ratings_in_this_form
            kwargs['all_images_in_this_form'] = all_images_in_this_form
            kwargs['all_tags_in_this_form'] = all_tags_in_this_form
            form_d = json.loads(form_data['form'])
            #form_d = form_data['form']
            for index, item in enumerate(form_d):
                kwargs['item'] = item
                kwargs['form'] = form_ob
                kwargs['customer_template'] = None
                update_template(previous_field_ids, updated_options, index+1, **kwargs)
            print "deleted tme"
            deleted_fields = list(set(all_fields_ids) - set(previous_field_ids))
            print "deleted fields"
            print deleted_fields
            all_headers_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_image_overlay_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_checkboxes_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_labels_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_paragraphs_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_signatures_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_radiobuttons_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_textfields_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_datepickers_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_dropdowns_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_linebreaks_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_numbers_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_textareas_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_ranges_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_cameras_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_ratings_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_images_in_this_form.filter(field_id__in=deleted_fields).delete()
            all_tags_in_this_form.filter(field_id__in=deleted_fields).delete()

            deleted_options = list(set(all_option_field_ids) - set(updated_options))
            Options.objects.filter(option_field_id__in=deleted_options).delete()

            return Response({'message': 'Successfully Updated formdata'})

        raise Exception('You are an inactive user please verify your email first')
    else:
        raise Exception('Form Data is not available')

def update_template(previous_field_ids, updated_options, index, **data_dict):

    item = data_dict.get('item')
    form = data_dict.get('form')

    customer_template = data_dict.get('customer_template')
    all_headers_in_this_form = data_dict.get('all_headers_in_this_form')
    all_image_overlay_in_this_form = data_dict.get('all_image_overlay_in_this_form')
    all_checkboxes_in_this_form = data_dict.get('all_checkboxes_in_this_form')
    all_paragraphs_in_this_form = data_dict.get('all_paragraphs_in_this_form')
    all_signatures_in_this_form = data_dict.get('all_signatures_in_this_form')
    all_numbers_in_this_form = data_dict.get('all_numbers_in_this_form')
    all_radiobuttons_in_this_form = data_dict.get('all_radiobuttons_in_this_form')
    all_textfields_in_this_form = data_dict.get('all_textfields_in_this_form')
    all_datepickers_in_this_form = data_dict.get('all_datepickers_in_this_form')
    all_dropdowns_in_this_form = data_dict.get('all_dropdowns_in_this_form')
    all_labels_in_this_form = data_dict.get('all_labels_in_this_form')
    all_linebreaks_in_this_form = data_dict.get('all_linebreaks_in_this_form')
    all_textareas_in_this_form = data_dict.get('all_textareas_in_this_form')
    all_ranges_in_this_form = data_dict.get('all_ranges_in_this_form')
    all_cameras_in_this_form = data_dict.get('all_cameras_in_this_form')
    all_ratings_in_this_form = data_dict.get('all_ratings_in_this_form')
    all_images_in_this_form = data_dict.get('all_images_in_this_form')
    all_tags_in_this_form = data_dict.get('all_tags_in_this_form')
    if item['element'] == 'Header':
        headers = all_headers_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if headers:
            previous_field_ids.append(item.get('id'))
            headers.update(
                                       form=form,
                                       label=item.get('text', None),
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', headers[0].group),
                                       placeholder=item.get('content', None),
                step=index,
                customer_template=customer_template
            )
        else:
            HeaderField.objects.create(
                                       form=form,
                                       label=item.get('text', None),
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', False),
                                       placeholder=item.get('content', None),
                customer_template= customer_template,
                step=index

            )
        return

    if item['element'] == 'Label':
        labels = all_labels_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if labels:
            previous_field_ids.append(item.get('id'))
            labels.update(
                                       label=item.get('text', None),
                                       form=form,
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', labels[0].group),
                                       placeholder=item.get('content', None),
                step=index,
                customer_template=customer_template
            )
        else:
            LabelField.objects.create(
                                       label=item.get('text', None),
                                       form=form,
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', False),
                                       placeholder=item.get('content', None),
                customer_template=customer_template,
                step=index
            )

        return

    if item['element'] == 'LineBreak':
        linebreaks = all_linebreaks_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if linebreaks:
            previous_field_ids.append(item.get('id'))
            linebreaks.update(
                                       label=item.get('text', None),
                                       form=form,
                                       field_id=item.get('id', None),
                                       is_required=item.get('required', False),
                                       bold=item.get('bold', False),
                                       italic=item.get('italic', False),
                                       static=item.get('static', False),
                                       group=item.get('group', linebreaks[0].group),
                step=index,
                customer_template=customer_template
            )
        else:
            LineBreakField.objects.create(

                label=item.get('text', None),
                form=form,
                field_id=item.get('id', None),
                is_required=item.get('required', False),
                bold=item.get('bold', False),
                italic=item.get('italic', False),
                static=item.get('static', False),
                group=item.get('group', False),
                customer_template=customer_template,
                step=index
            )
        return

    if item['element'] == 'Checkboxes':
        checkbox = all_checkboxes_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if checkbox:
            previous_field_ids.append(item.get('id'))
            checkbox.update(
                label=item.get('label', None),
                form=form,
                help_text=item.get('text', None),
                name=item.get('field_name', None),
                field_id=item.get('id', None),
                is_required=item.get('required', False),
                group=item.get('group', checkbox[0].group),
                canHaveAnswer=item.get('canHaveAnswer', False),
                step=index,
                customer_template=customer_template
            )

            for option in item['options']:
                option_ob = Options.objects.filter(singlecheckbox=checkbox[0], option_field_id=option.get('key'))
                if option_ob:
                    updated_options.append(option.get('key'))
                    option_ob.update(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        singlecheckbox=checkbox[0]
                    )
                else:
                    Options.objects.create(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        singlecheckbox=checkbox[0]
                    )
        else:
            checkbox = SingleCheckBox.objects.create(
                                                       label=item.get('label', None),
                                                       form=form,
                                                       help_text=item.get('text', None),
                                                       name=item.get('field_name', None),
                                                       field_id=item.get('id', None),
                                                       is_required=item.get('required', False),
                                                       group=item.get('group', False),
                                                       canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )


            if checkbox:

                for option in item['options']:
                    Options.objects.create(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        singlecheckbox=checkbox
                    )
            return

    if item['element'] == 'Paragraph':

        paragraph =all_paragraphs_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if paragraph:
            previous_field_ids.append(item.get('id'))
            paragraph.update(
                                        label=item.get('label', None),
                                        form=form,
                                        help_text=item.get('text', None),
                                        name=item.get('field_name', None),
                                        field_id=item.get('id', None),
                                        is_required=item.get('required', False),
                                        bold=item.get('bold', False),
                                        italic=item.get('italic', False),
                                        static=item.get('static', False),
                                        group=item.get('group', paragraph[0].group),
                step=index,
                customer_template=customer_template,
            )
        else:
            ParagraphField.objects.create(
                                        label=item.get('label', None),
                                        form=form,
                                        help_text=item.get('text', None),
                                        name=item.get('field_name', None),
                                        field_id=item.get('id', None),
                                        is_required=item.get('required', False),
                                        bold=item.get('bold', False),
                                        italic=item.get('italic', False),
                                        static=item.get('static', False),
                                        group=item.get('group', False),
                customer_template=customer_template,
                step=index
            )
        return

    if item['element'] == 'Signature':
        signature = all_signatures_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if signature:
            previous_field_ids.append(item.get('id'))
            signature.update(
                                            label=item.get('label', None),
                                            form=form,
                                            help_text=item.get('text', None),
                                            name=item.get('field_name', None),
                                            field_id=item.get('id', None),
                                            is_required=item.get('required', False),
                                            group=item.get('group', False),
                step=index,
                customer_template=customer_template,
            )
        else:

            SignatureField.objects.create(
                                            label=item.get('label', None),
                                            form=form,
                                            help_text=item.get('text', None),
                                            name=item.get('field_name', None),
                                            field_id=item.get('id', None),
                                            is_required=item.get('required', False),
                                            group=item.get('group', False),
                customer_template=customer_template,
                step=index
            )

        return

    if item['element'] == 'RadioButtons':

        radiobuttons = all_radiobuttons_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if radiobuttons:
            previous_field_ids.append(item.get('id'))
            radiobuttons.update(
                                                       label=item.get('label', None),
                                                       form=form,
                                                       help_text=item.get('text', None),
                                                       name=item.get('field_name', None),
                                                       field_id=item.get('id', None),
                                                       is_required=item.get('required', False),
                                                       group=item.get('group', False),
                                                       canHaveAnswer=item.get('canHaveAnswer', False),
                step=index,
                customer_template=customer_template,
            )

            for option in item['options']:
                option_ob = Options.objects.filter(singleradiobox=radiobuttons[0], option_field_id=option.get('key'))
                if option_ob:
                    updated_options.append(option.get('key'))
                    option_ob.update(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        singleradiobox=radiobuttons[0]
                    )
                else:
                    Options.objects.create(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        singleradiobox=radiobuttons[0]
                    )
        else:
            radiobox = SingleRadioBox.objects.create(
                                                       label=item.get('label', None),
                                                       form=form,
                                                       help_text=item.get('text', None),
                                                       name=item.get('field_name', None),
                                                       field_id=item.get('id', None),
                                                       is_required=item.get('required', False),
                                                       group=item.get('group', False),
                                                       canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )

            if radiobox:

                for option in item['options']:
                    Options.objects.create(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        singleradiobox=radiobox
                    )
            return

    if item['element'] == 'TextInput':
        textfield = all_textfields_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if textfield:
            previous_field_ids.append(item.get('id'))
            textfield.update(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                step=index,
                customer_template=customer_template,
            )
        else:
            TextField.objects.create(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )
        return

    if item['element'] == 'NumberInput':

        numbers = all_numbers_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if numbers:
            previous_field_ids.append(item.get('id'))
            numbers.update(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
            step=index,
                customer_template=customer_template,

            )
        else:
            NumberInput.objects.create(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )

        return

    if item['element'] == 'TextArea':

        textareas = all_textareas_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if textareas:
            previous_field_ids.append(item.get('id'))
            textareas.update(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                step=index,
                customer_template=customer_template,

            )
        else:
            TextArea.objects.create(
                                 label=item.get('label', None),
                                 placeholder=item.get('placeholder', None),
                                 max_length=item.get('max_length', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )

        return
    if item['element'] == 'Range':
        ranges = all_ranges_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if ranges:
            previous_field_ids.append(item.get('id'))
            ranges.update(
                                 label=item.get('label', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 min_label=item.get('min_label', None),
                                 max_label=item.get('max_label', None),
                                 step=index,
                                 default_value=item.get('default_value', None),
                                 min_value=item.get('min_value', None),
                                 stepno=item.get('stepno', None),
                                 max_value=item.get('max_value', None),
                                 group=item.get('group', False),
                customer_template=customer_template,

            )
        else:
            RangeField.objects.create(
                                 label=item.get('label', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 min_label=item.get('min_label', None),
                                 max_label=item.get('max_label', None),
                                 customer_template=customer_template,
                                 default_value=item.get('default_value', None),
                                 min_value=item.get('min_value', None),
                                 max_value=item.get('max_value', None),
                                 group=item.get('group', False),
                step=index,
            )

        return

    if item['element'] == 'Camera':
        cameras = all_cameras_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if cameras:
            previous_field_ids.append(item.get('id'))
            cameras.update(
                            label=item.get('text', None),
                            form=form,
                            help_text=item.get('text', None),
                            name=item.get('field_name', None),
                            field_id=item.get('id', None),
                            is_required=item.get('required', False),
                            group=item.get('group', False),
                step=index,
                customer_template=customer_template,
            )

        else:
            Camera.objects.create(
                                    label=item.get('text', None),
                                    form=form,
                                    help_text=item.get('text', None),
                                    name=item.get('field_name', None),
                                    field_id=item.get('id', None),
                                    is_required=item.get('required', False),
                group=item.get('group', False),
                customer_template=customer_template,
                step=index
            )

        return

    if item['element'] == 'Rating':
        ratings = all_ratings_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if ratings:
            previous_field_ids.append(item.get('id'))
            ratings.update(
                                 label=item.get('label', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                step=index,
                customer_template=customer_template,

            )
        else:
            RatingField.objects.create(
                                 label=item.get('label', None),
                                 form=form,
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )
        return

    if item['element'] == 'Image':
        images = all_images_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if images:
            previous_field_ids.append(item.get('id'))
            images.update(
                                 label=item.get('text', None),
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 src=item.get('src', None),
                center=item.get('center', None),
                step=index,
                customer_template=customer_template,

            )
        else:
            ImageField.objects.create(
                                 label=item.get('text', None),
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                                 src=item.get('src', None),
                center=item.get('center', None),
                customer_template=customer_template,
                step=index,
                form=form
            )

        return

    if item['element'] == 'ImageMarker':
        image_overlay = all_image_overlay_in_this_form.filter(form=form, customer_template=customer_template,
                                                       field_id=item.get(
            'id'))
        if image_overlay:
            previous_field_ids.append(item.get('id'))
            image_overlay.update(
                                 label=item.get('text', None),
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                step=index,
                customer_template=customer_template,
                form=form

            )
        else:
            ImageOverlay.objects.create(
                                 label=item.get('text', None),
                                 help_text=item.get('text', None),
                                 name=item.get('field_name', None),
                                 field_id=item.get('id', None),
                                 is_required=item.get('required', False),
                                 group=item.get('group', False),
                step=index,
                customer_template=customer_template,
                form=form

            )

        return

    if item['element'] == 'DatePicker':

        datepicker = all_datepickers_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if datepicker:
            previous_field_ids.append(item.get('id'))
            datepicker.update(
                                     label=item.get('label', None),
                                     form=form,
                                     help_text=item.get('text', None),
                                     name=item.get('field_name', None),
                                     field_id=item.get('id', None),
                                     is_required=item.get('required', False),
                                     group=item.get('group', False),
                                     defaulttoday=item.get('defaultToday', False),
                                     readonly=item.get('readOnly', False),
                step=index,
                customer_template=customer_template,

            )
        else:
            DateTimeField.objects.create(
                                     label=item.get('label', None),
                                     form=form,
                                     help_text=item.get('text', None),
                                     name=item.get('field_name', None),
                                     field_id=item.get('id', None),
                                     is_required=item.get('required', False),
                                     group=item.get('group', False),
                                     defaulttoday=item.get('defaultToday', False),
                                     readonly=item.get('readOnly', False),
                customer_template=customer_template,
                step=index
            )
        return

    if item['element'] == 'Dropdown':


        dropdown = all_dropdowns_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        if dropdown:
            previous_field_ids.append(item.get('id'))
            dropdown.update(
                                           label=item.get('label', None),
                                           form=form,
                                           help_text=item.get('text', None),
                                           name=item.get('field_name', None),
                                           field_id=item.get('id', None),
                                           is_required=item.get('required', False),
                                           group=item.get('group', False),
                                           canHaveAnswer=item.get('canHaveAnswer', False),
                step=index,
                customer_template=customer_template,
            )
            for option in item['options']:
                option_ob = Options.objects.filter(dropdown=dropdown[0], option_field_id=option.get('key'))
                if option_ob:
                    updated_options.append(option.get('key'))
                    option_ob.update(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        dropdown=dropdown[0]
                    )
                else:
                    Options.objects.create(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        dropdown=dropdown[0]
                    )
        else:
            dropdown = DropDown.objects.create(
                                           label=item.get('label', None),
                                           form=form,
                                           help_text=item.get('text', None),
                                           name=item.get('field_name', None),
                                           field_id=item.get('id', None),
                                           is_required=item.get('required', False),
                                           group=item.get('group', False),
                                           canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )

            if dropdown:

                for option in item['options']:
                    Options.objects.create(
                        option_label=option.get('label', None),
                        option_value=option.get('value', None),
                        option_field_id=option.get('key', None),
                        selected=option.get('selected', False),
                        option_text=option.get('text', None),
                        dropdown=dropdown
                    )
            return

    if item['element'] == 'Tags':


        tags = all_tags_in_this_form.filter(form=form, customer_template=customer_template, field_id=item.get(
            'id'))
        print tags
        if tags:
            print "updating"
            previous_field_ids.append(item.get('id'))
            tags.update(
                                           label=item.get('label', None),
                                           form=form,
                                           help_text=item.get('text', None),
                                           name=item.get('field_name', None),
                                           field_id=item.get('id', None),
                                           is_required=item.get('required', False),
                                           group=item.get('group', False),
                                           canHaveAnswer=item.get('canHaveAnswer', False),
                step=index,
                customer_template=customer_template,
            )
            for option in item['options']:
                option_ob = Options.objects.filter(tags=tags[0], option_field_id=option.get('key'))
                if option_ob:
                    updated_options.append(option.get('key'))
                    option_ob.update(
                                       option_text=option.get('text', None),
                                       option_value=option.get('value', None),
                                       option_field_id=option.get('key', None),
                                       option_label=option.get('label', None),
                                       selected=option.get('selected', False),
                                       tags=tags[0]
                )
                else:
                    Options.objects.create(
                                       option_text=option.get('text', None),
                                       option_value=option.get('value', None),
                                       option_field_id=option.get('key', None),
                                       option_label=option.get('label', None),
                                       selected=option.get('selected', False),
                                       tags=tags[0],

                )
        else:
            print "tags elkse"
            tag = Tags.objects.create(
                                           label=item.get('label', None),
                                           form=form,
                                           help_text=item.get('text', None),
                                           name=item.get('field_name', None),
                                           field_id=item.get('id', None),
                                           is_required=item.get('required', False),
                                           group=item.get('group', False),
                                           canHaveAnswer=item.get('canHaveAnswer', False),
                customer_template=customer_template,
                step=index
            )

            if tag:

                for option in item['options']:
                    Options.objects.create(
                                       option_text=option.get('text', None),
                                       option_value=option.get('value', None),
                                       option_field_id=option.get('key', None),
                                       option_label=option.get('label', None),
                                       selected=option.get('selected', False),
                                       tags=tag
                )
            print "returning"
            return

@api_view(['GET'])
def form_listing(request):

    user = request.user
    forms = AdminFormModules.objects.filter(Q(user__role_type='A')| Q(user__role_type='S'))
    # paginator = PageNumberPagination()
    # paginator.page_size = PAGE_SIZE
    # paginated_data = paginator.paginate_queryset(forms, request)
    serializer = FormSerializer(forms, many=True)
    data = serializer.data
    for i, item in enumerate(data):
        if data[i].get('is_default') == True:
            default_form = data.pop(i)
            data.insert(0, default_form)
            #return Response(data)
    return Response(data)
    #return paginator.get_paginated_response(data)

@api_view(['GET'])
def get_existing_templates(request):

    templates = AdminFormModules.objects.filter(Q(user__role_type='A')|Q(user__role_type='S'))
    final_form = OrderedDict()
    final_form['all_admin_templates'] = []
    for template in templates:
        template_data = OrderedDict()
        template_data['title'] = template.title
        template_data['type'] = "inputmodule"
        template_data['description'] = template.description
        template_data['module_price'] = template.module_price
        template_data['form_id'] = template.id
        template_data['min'] = template.min
        template_data['max'] = template.max
        template_data['form'] = []
        template_data['form_conditions'] = []
        conditions_in_form = Conditions.objects.filter(form=template).values('if_field', 'state', 'condition', 'field',
                                                                             'value')
        for condition in conditions_in_form:
            template_data['form_conditions'].append(condition)
        get_template_data(template_data, template)
        #groups_in_form = InputGroup.objects.filter(form=template)
        # for group in groups_in_form:
        #     group_info = get_template_groups(template_data, group)
        #     template_data['form'].append(group_info)
        sorted_template_data = sorted(template_data['form'], key=itemgetter('step'))
        print "this is sorted template data"
        print sorted_template_data
        template_data['form'] = sorted_template_data
        for item in sorted_template_data:
            item.pop('step')
        print "SORTED"
        final_form['all_admin_templates'].append(template_data)
    return Response(final_form)

@api_view(['GET', 'POST'])
def view_customer_form(request, form_id):
    form_id_from_params = request.query_params.get('customer_form_id', None)

    authorization_header = request.META.get('HTTP_AUTHORIZATION', None)
    if form_id_from_params:
        form_id = form_id_from_params
    try:
        customer_form = CustomerForms.objects.get(id=form_id)
    except(CustomerForms.DoesNotExist):
        raise Exception('Customer Form Does Not Exist')
    customer_form_data = OrderedDict()
    customer_form_data['title'] = customer_form.title
    customer_form_data['customer_form_id'] = form_id
    customer_form_data['status'] = customer_form.status
    customer_form_data['description'] = customer_form.description
    customer_form_data['form_price'] = customer_form.form_price
    customer_form_data['customer_form'] = []
    customer_form_data['functional_modules'] = []
    all_welcome_modules = WelcomeModuleCustomer.objects.filter(customer_form=customer_form)
    if all_welcome_modules:
        for welcomemodule in all_welcome_modules:
            welcomemodule_data = {}
            welcomemodule_data.update({'type': 'welcomemodule'})
            welcomemodule_data['data'] = []
            serializer = WelcomeModuleCustomerSerializer(welcomemodule, context={'request': request})
            welcomemodule_data['data'].append(serializer.data)
            customer_form_data['functional_modules'].append(welcomemodule_data)

    all_submit_modules = SubmitModuleCustomer.objects.filter(customer_form=customer_form)
    if all_submit_modules:
        for submitmodule in all_submit_modules:
            submitmodule_data = {}
            submitmodule_data.update({'type': 'submitmodule'})
            submitmodule_data['data'] = []
            data_dict = {}
            data_dict['message'] = submitmodule.message
            data_dict['module_price'] = submitmodule.module_price
            data_dict['cfm_id'] = submitmodule.id
            submitmodule_data['data'].append(data_dict)
            customer_form_data['functional_modules'].append(submitmodule_data)
    all_unlock_modules = UnlockModuleCustomer.objects.filter(customer_form=customer_form)
    if all_unlock_modules:
        for unlockmodule in all_unlock_modules:
            unlockmodule_data = {}
            unlockmodule_data.update({'type': 'unlockmodule'})
            data_dict = {}
            unlockmodule_data['data'] = []
            data_dict['message'] = unlockmodule.message
            data_dict['module_price'] = unlockmodule.module_price
            data_dict['cfm_id'] = unlockmodule.id
            unlockmodule_data['data'].append(data_dict)
            customer_form_data['functional_modules'].append(unlockmodule_data)
    all_dropbox_modules = DropboxModuleCustomer.objects.filter(customer_form=customer_form)
    if all_dropbox_modules:
        for dropboxmodule in all_submit_modules:
            dropboxmodule_data = {}
            dropboxmodule_data.update({'type': 'dropboxmodule'})
            data_dict = {}
            dropboxmodule_data['data'] = []
            data_dict['module_price'] = dropboxmodule.module_price
            data_dict['cfm_id'] = dropboxmodule.id
            if authorization_header:
                if request.user.dropbox_token:
                    data_dict['connected'] = True
                else:
                    data_dict['connected'] = False
            dropboxmodule_data['data'].append(data_dict)
            customer_form_data['functional_modules'].append(dropboxmodule_data)

    all_email_modules = EmailModuleCustomer.objects.filter(customer_form=customer_form)
    if all_email_modules:
        for emailmodule in all_email_modules:
            emailmodule_data = {}
            emailmodule_data.update({'type': 'emailmodule'})
            data_dict = {}
            emailmodule_data['data'] = []
            data_dict['module_price'] = emailmodule.module_price
            data_dict['cfm_id'] = emailmodule.id
            emailmodule_data['data'].append(data_dict)
            customer_form_data['functional_modules'].append(emailmodule_data)

    all_drive_modules = GoogleDriveModuleCustomer.objects.filter(customer_form=customer_form)
    if all_drive_modules:
        for drivemodule in all_submit_modules:
            drivemodule_data = {}
            drivemodule_data.update({'type': 'drivemodule'})
            data_dict = {}
            drivemodule_data['data'] = []
            data_dict['module_price'] = drivemodule.module_price
            data_dict['cfm_id'] = drivemodule.id
            if authorization_header:
                if request.user.google_drive_token:
                    data_dict['connected'] = True
                else:
                    data_dict['connected'] = False
            drivemodule_data['data'].append(data_dict)
            customer_form_data['functional_modules'].append(drivemodule_data)

    form_templates = CustomerTemplates.objects.filter(customer_form=customer_form)
    for template in form_templates:

        template_data = OrderedDict()
        template_data['title'] = template.title
        template_data['customertemplate_id'] = template.id
        template_data['description'] = template.description
        template_data['module_price'] = template.module_price
        template_data['min'] = template.min
        template_data['max'] = template.max
        template_data['orderno'] = template.orderno
        template_data['type'] = 'inputmodule'
        template_data['form'] = []
        template_data['form_conditions'] = []
        conditions_in_form = Conditions.objects.filter(customer_template=template).values('if_field', 'state',
                                                                                          'condition', 'field',
                                                                                          'value')
        for condition in conditions_in_form:
            template_data['form_conditions'].append(condition)

        get_template_data(template_data, templates=None, customer_template=template)
        sorted_template_data = sorted(template_data['form'], key=itemgetter('step'))
        template_data['form'] = sorted_template_data
        # for item in sorted_template_data:
        #     item.pop('step')
        customer_form_data['customer_form'].append(template_data)
    sorted_form_templates = sorted(customer_form_data['customer_form'], key=itemgetter('orderno'))
    customer_form_data['customer_form'] = sorted_form_templates
    return Response(customer_form_data)


@api_view(['GET'])
def view_admin_template(request):

    form_id = request.query_params.get('form_id', None)
    template = AdminFormModules.objects.get(id=form_id)
    template_data = OrderedDict()
    template_data['title'] = template.title
    template_data['form_id'] = form_id
    template_data['description'] = template.description
    template_data['module_price'] = template.module_price
    template_data['min'] = template.min
    template_data['max'] = template.max
    template_data['form'] = []
    template_data['form_conditions'] = []
    conditions_in_form = Conditions.objects.filter(form=template).values('if_field', 'state', 'condition', 'field',
                                                                         'value')
    for condition in conditions_in_form:
        template_data['form_conditions'].append(condition)
    get_template_data(template_data, templates=template, customer_template=None)
    sorted_template_data = sorted(template_data['form'], key=itemgetter('step'))
    for item in sorted_template_data:
        item.pop('step')
    template_data['form'] = sorted_template_data
    return Response(template_data)

@api_view(['GET'])
def delete_form(request):

    form_id = request.query_params.get('form_id')
    form = AdminFormModules.objects.get(id=form_id)
    form.delete()
    return Response({'message': 'Form has been deleted Successfully'})

@api_view(['POST'])
def update_welcome_module_admin(request):

    welcome_module_data = request.data
    if welcome_module_data:
        welcomemodule = WelcomeModuleAdmin.objects.get()

        welcomemodule.image_activated = welcome_module_data.get('image_activated', welcomemodule.image_activated)
        welcomemodule.is_enabled = welcome_module_data.get('is_enabled', welcomemodule.is_enabled)
        if welcomemodule.image_activated:
            welcomemodule.image = welcome_module_data.get('image', welcomemodule.image)
        welcomemodule.video_activated = welcome_module_data.get('video_activated', welcomemodule.video_activated)

        if welcomemodule.video_activated:
            welcomemodule.video = welcome_module_data.get('video', welcomemodule.video)

        welcomemodule.message_activated = welcome_module_data.get('message_activated', welcomemodule.message_activated)

        if welcomemodule.message_activated:
            welcomemodule.message = welcome_module_data.get('message', welcomemodule.message)

        welcomemodule.logo_activated = welcome_module_data.get('logo_activated', welcomemodule.logo_activated)

        if welcomemodule.logo_activated:
            welcomemodule.logo = welcome_module_data.get('logo', welcomemodule.logo)

        welcomemodule.module_price = welcome_module_data.get('module_price', welcomemodule.module_price)
        welcomemodule.save()
        serializer = WelcomeModuleAdminSerializer(welcomemodule, context={'request': request})
        return Response(serializer.data)

@api_view(['POST'])
def update_submit_module_admin(request):

    submit_module_data = request.POST.dict()
    if submit_module_data:
        submitmodule = SubmitModuleAdmin.objects.get()

        submitmodule.message = submit_module_data.get('message', submitmodule.message)
        if submit_module_data['is_enabled'] == 'True':
            submitmodule.is_enabled = True
        elif submit_module_data['is_enabled'] == 'False':
            submitmodule.is_enabled = False
        else:
            pass
        #submitmodule.is_enabled = submit_module_data.get('is_enabled', submitmodule.is_enabled)
        submitmodule.module_price = submit_module_data.get('module_price', submitmodule.module_price)

        submitmodule.save()
        serializer = SubmitModuleAdminSerializer(submitmodule)
        return Response(serializer.data)

@api_view(['POST'])
def update_dropbox_module_admin(request):

    dropbox_module_data = request.POST.dict()
    if dropbox_module_data:
        dropboxmodule = DropboxModuleAdmin.objects.get()
        dropboxmodule.is_enabled = dropbox_module_data.get('is_enabled', dropboxmodule.is_enabled)
        dropboxmodule.module_price = dropbox_module_data.get('module_price', dropboxmodule.module_price)

        dropboxmodule.save()
        serializer = DropboxModuleAdminSerializer(dropboxmodule)
        return Response(serializer.data)

@api_view(['POST'])
def update_email_module_admin(request):

    email_module_data = request.POST.dict()
    if email_module_data:
        emailmodule = EmailModuleAdmin.objects.get()
        emailmodule.is_enabled = email_module_data.get('is_enabled', emailmodule.is_enabled)
        emailmodule.module_price = email_module_data.get('module_price', emailmodule.module_price)

        emailmodule.save()
        serializer = DropboxModuleAdminSerializer(emailmodule)
        return Response(serializer.data)


@api_view(['GET'])
def get_dropbox_module_admin(request):

    try:
        dropboxmodule = DropboxModuleAdmin.objects.get()
    except(DropboxModuleAdmin.DoesNotExist):
        raise Exception('No Dropbox Module')
    serializer =DropboxModuleAdminSerializer(dropboxmodule)
    return Response(serializer.data)

@api_view(['GET'])
def get_email_module_admin(request):

    try:
        emailmodule = EmailModuleAdmin.objects.get()
    except(EmailModuleAdmin.DoesNotExist):
        raise Exception('No Dropbox Module')
    serializer =EmailModuleAdminSerializer(emailmodule)
    return Response(serializer.data)

@api_view(['POST'])
def update_drive_module_admin(request):

    drive_module_data = request.POST.dict()
    if drive_module_data:
        drivemodule = GoogleDriveModuleAdmin.objects.get()
        # serializer = SubmitModuleAdminSerializer(data=submit_module_data)
        # if serializer.is_valid():
        #     serializer.save()
        #     return Response(serializer.data)
        # else: return Response(serializer.errors)
        drivemodule.is_enabled = drive_module_data.get('is_enabled', drivemodule.is_enabled)
        drivemodule.module_price = drive_module_data.get('module_price', drivemodule.module_price)

        drivemodule.save()
        serializer = GoogleDriveModuleAdminSerializer(drivemodule)
        return Response(serializer.data)

@api_view(['GET'])
def get_drive_module_admin(request):

    try:
        drivemodule = GoogleDriveModuleAdmin.objects.get()
    except(DropboxModuleAdmin.DoesNotExist):
        raise Exception('No Dropbox Module')
    serializer =GoogleDriveModuleAdminSerializer(drivemodule)
    return Response(serializer.data)


@api_view(['POST'])
def update_unlock_module_admin(request):

    unlock_module_data = request.POST.dict()
    if unlock_module_data:
        unlockmodule = UnlockModuleAdmin.objects.get()
        # serializer = SubmitModuleAdminSerializer(data=submit_module_data)
        # if serializer.is_valid():
        #     serializer.save()
        #     return Response(serializer.data)
        # else: return Response(serializer.errors)

        unlockmodule.message = unlock_module_data.get('message', unlockmodule.message)
        unlockmodule.is_enabled = unlock_module_data.get('is_enabled', unlockmodule.is_enabled)
        unlockmodule.module_price = unlock_module_data.get('module_price', unlockmodule.module_price)

        unlockmodule.save()
        serializer = UnlockModuleAdminSerializer(unlockmodule)
        return Response(serializer.data)

@api_view(['GET'])
def get_welcome_module_admin(request):

    try:
        welcomemodule = WelcomeModuleAdmin.objects.get()
    except(WelcomeModuleAdmin.DoesNotExist):
        raise Exception('No Welcome Module')
    serializer =WelcomeModuleAdminSerializer(welcomemodule, context={'request':request})
    return Response(serializer.data)

@api_view(['GET'])
def get_unlock_module_admin(request):

    try:
        unlockmodule = UnlockModuleAdmin.objects.get()
    except(UnlockModuleAdmin.DoesNotExist):
        raise Exception('No Unlock Module')
    serializer =UnlockModuleAdminSerializer(unlockmodule,context={'request':request})
    return Response(serializer.data)


@api_view(['GET'])
def get_submit_module_admin(request):

    try:
        submitmodule = SubmitModuleAdmin.objects.get()
    except(SubmitModuleAdmin.DoesNotExist):
        raise Exception('No Submit Module')
    serializer =SubmitModuleAdminSerializer(submitmodule,context={'request':request})
    return Response(serializer.data)

@api_view(['GET'])
def dropbox_integration_start(request):
    if request.user.dropbox_token:
        print "User Connected"
        connected = True
        return Response({'message': 'User already connected to dropbox', 'connected': connected})
    print "this is user"
    print request.user
    user = str(request.user.username)
    state = user
    app_key = settings.DROPBOX_APP_KEY
    red_url = reverse('finish_dropbox_integration')
    print red_url
    redirect_uri = (get_current_site(request).domain)[:-1] + red_url
    print redirect_uri
    authorize_url = 'https://www.dropbox.com/1/oauth2/authorize/?redirect_uri={}&response_type=code&client_id={' \
                    '}&state={}'.format(redirect_uri, app_key, state)
    return redirect(authorize_url)

@api_view(['GET'])
def dropbox_integration_finish(request):
    authorization_code = request.query_params.get('code', None)
    user = request.query_params.get('state', None)
    client_id = settings.DROPBOX_APP_KEY
    client_secret = settings.DROPBOX_APP_SECRET
    url = 'https://api.dropboxapi.com/1/oauth2/token'
    grant_type = "authorization_code"
    redirect_uri = (get_current_site(request).domain)[:-1] + reverse('finish_dropbox_integration')
    post_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': grant_type,
        'code': authorization_code,
        'redirect_uri': redirect_uri
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    resp = requests.post(url=url, data=post_data, headers=headers)
    user_response_data = resp.json()
    user_token = user_response_data['access_token']
    user = CustomUser.objects.get(username=user)
    user.dropbox_token = user_token
    user.save()
    return Response({'message': 'User Connected to dropbox', 'access_token': user_token})

@api_view(['GET'])
def drive_integration_finish(request):

    redirect_uri = (get_current_site(request).domain)[:-1] + reverse('finish_drive_integration')
    authorization_code = request.query_params.get('code', None)
    user = request.query_params.get('state', None)
    if authorization_code:
        params = {
            'client_id': settings.GOOGLE_DRIVE_CLIENT_ID,
            'client_secret': settings.GOOGLE_DRIVE_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'code': authorization_code
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        access_token_url = settings.GOOGLE_DRIVE_TOKEN_URL
        resp = requests.post(url=access_token_url, data=params, headers=headers)
        user_data = resp.content
        json_data = json.loads(user_data)
        access_token = json_data['access_token']
        u = CustomUser.objects.get(username=user)
        u.google_drive_token = access_token
        u.save()
        return Response({'message': 'User connected to google drive', 'access_token': access_token})



@api_view(['GET'])
def drive_integration_start(request):
    if request.user.google_drive_token:
        connected = True
        print connected
        return Response({'message': 'User already connected to Google Drive', 'connected': connected})
    scope = 'https://www.googleapis.com/auth/drive'
    response_type = 'code'
    state = str(request.user.username)
    redirect_uri = (get_current_site(request).domain)[:-1] + reverse('finish_drive_integration')
    print redirect_uri
    authorize_url = settings.GOOGLE_DRIVE_AUTH_URL + '?' + 'redirect_uri={}&response_type={}&client_id={}&' \
                                                           'scope={}&state={}'.format(redirect_uri, response_type,
                                                                                      settings.GOOGLE_DRIVE_CLIENT_ID, scope, state)
    print authorize_url
    return redirect(authorize_url)

@api_view(['GET'])
def change_form_status(request):

    form_id = request.query_params.get('form_id', None)
    status = request.query_params.get('status', None)
    if form_id and status:
        try:
            form = CustomerForms.objects.get(id=form_id)
        except(CustomUser.DoesNotExist):
            raise Exception('This form does not exist')
        form.status = status
        form.save()
        return Response({'message': 'Status Updated Successfully'})
    else:
        raise Exception('Either form_id or status is missing')

@api_view(['GET'])
def organisation_form_listing(request):

    organisation_id = request.query_params.get('organisation_id', None)
    status = request.query_params.get('status', None)
    if organisation_id:
        organisation_forms = AdminFormModules.objects.filter(user__organisation__id=organisation_id, status=status)
        # paginator = PageNumberPagination()
        # paginator.page_size = PAGE_SIZE
        # paginated_data = paginator.paginate_queryset(organisation_forms, request)
        # serializer = FormSerializer(paginated_data, many=True)
        # return paginator.get_paginated_response(serializer.data)
        serializer = FormSerializer(organisation_forms, many=True)
        return Response(serializer.data)
    else:
        raise Exception('Organisation Id is missing')

@api_view(['POST'])
def add_to_cart_for_customer_forms(request):

    cart_info = request.data
    user = request.user
    customer_form_id = cart_info['customer_form_id']
    customer_form = CustomerForms.objects.get(id=customer_form_id)
    declared_fee = DeclaredPaymentFee.objects.get(id=1)
    form_amount = float(declared_fee.customer_form_fee)
    if user and cart_info:
        Cart.objects.create(user=user,
                            customer_form=customer_form,
                            form_amount=form_amount)
        return Response({'message': 'Form Added to Cart Successfully'})
    else:
        raise Exception('Insufficient Data')

@api_view(['GET'])
def get_cart(request):

    user = request.user
    form_id = request.query_params.get('form_id', None)
    if user and form_id:
        form = CustomerForms.objects.get(id=form_id)
        #templates_in_cart = Cart.objects.filter(user=user, form=form_id)
        #serializer = CartSerializer(templates_in_cart, many=True)
        # return Response(serializer.data)
        ser = CustomerFormSerializer(form)
        return Response(ser.data)
    else:
        raise Exception('Insufficient Data')

@api_view(['GET'])
def cancel_item_cart(request):

    user = request.user
    template_id = request.query_params.get('template_id', None)
    if user and template_id:
        templates = Cart.objects.filter(template_id=template_id)
        templates.delete()
        return Response({'message': 'Template Deleted Successfully'})
    else:
        raise Exception('Insufficient Params')

@api_view(['POST'])
@transaction.atomic
def customer_create_form(request):

    form_data = request.data
    status = request.query_params.get('status', None)
    if form_data:
        form_title = form_data['title']
        form_description = form_data['description']
        user = request.user
        publish_id = form_data.get('publish_id', None)
        form_price = 0
        form_d = form_data['form']
        if form_d:
            data_form = json.loads(form_d)
            # data_form = form_d
            # print data_form
        else:
            data_form = []
        functional_modules = form_data.get('functional_modules', None)
        if user.is_active:
            if publish_id:
                published_form = PublishFormHandling.objects.create(publish_form_id=publish_id)
                # data_form = form_d
                cust_form = CustomerForms.objects.get(id=publish_id)
                cust_form.is_deleted = True
                form = CustomerForms.objects.create(title=form_title,
                                                    description=form_description,
                                                    user=user,
                                                    created_by=user.username,
                                                    publish_id=published_form.publish_form_id,
                                                    status=status
                                                    )
            else:
                published_form = None
                form = CustomerForms.objects.create(title=form_title,
                                                    description=form_description,
                                                    user=user,
                                                    created_by=user.username,
                                                    publish_id=published_form,
                                                    status=status
                                                    )

            if functional_modules:
                func_modules = json.loads(functional_modules)
                functional_modules = func_modules
                for module in functional_modules:
                    module_type = module.get('type')
                    orderno = module.get('orderno')
                    print module_type
                    print "OrderNo {}".format(orderno)
                    module_data = module.get('data', None)
                    #module_data = module_data[0]
                    if module_type == 'welcomemodule':
                        image = module_data.get('image', None)
                        logo = module_data.get('logo', None)
                        print "these are image and logo"
                        print image
                        print logo
                        WelcomeModuleCustomer.objects.create(
                                                             message=module_data.get('message', None),
                                                             video=module_data.get('video', None),
                                                             image=image,
                                                             logo=logo,
                                                             customer_form=form,
                                                             user=user,
                                                             module_price=module_data.get('module_price', None),
                            orderno=orderno)
                    if module_type == 'submitmodule':
                        SubmitModuleCustomer.objects.create(user=user,
                                                            customer_form=form,
                                                            message=module_data.get('message', None),
                                                            module_price=module_data.get('module_price', None),
                                                            orderno=orderno
                                                            )
                    if module_type == 'unlockmodule':
                        UnlockModuleCustomer.objects.create(user=user,
                                                            customer_form=form,
                                                            message=module_data.get('message', None),
                                                            module_price=module_data.get('module_price', None),
                                                            orderno=orderno
                                                            )

                    if module_type == 'dropboxmodule':
                        DropboxModuleCustomer.objects.create(user=user,
                                                            customer_form=form,
                                                            module_price=module_data.get('module_price', None),
                                                             orderno=orderno
                                                            )
                    if module_type == 'emailmodule':
                        EmailModuleCustomer.objects.create(user=user,
                                                            customer_form=form,
                                                            module_price=module_data.get('module_price', None),
                                                            email=module_data.get('email', None),
                                                           orderno=orderno
                                                            )
                    if module_type == 'drivemodule':
                        GoogleDriveModuleCustomer.objects.create(user=user,
                                                             customer_form=form,
                                                             module_price=module_data.get('module_price', None),
                                                                 orderno=orderno
                                                             )

            for item in data_form:
                print "this is data"
                print item
                title = item.get('title', None)
                description = item.get('description', None)
                module_price = item.get('module_price', None)
                form_price += int(module_price)
                min = item.get('min', None)
                max = item.get('max', None)
                template_id = item.get('admin_template_id', None)
                print template_id
                orderno = item.get('orderno', None)
                try:
                    template_ob = AdminFormModules.objects.get(id=template_id)
                    template_ob.customers.add(form)
                except(AdminFormModules.DoesNotExist):
                    raise Exception('Template Does not Exist')
                conditions = item.get('conditions', None)
                if conditions:
                    form_conditions = conditions
                else:
                    form_conditions = None
                template_form = item.get('form', None)
                template = CustomerTemplates.objects.create(title=title,
                                                            description=description,
                                                            user=user,
                                                            created_by=user.username,
                                                            min=min,
                                                            max=max,
                                                            module_price=module_price,
                                                            customer_form=form,
                                                            orderno=orderno
                                                    )
                if form_conditions:
                    for condition in form_conditions:
                        Conditions.objects.create(if_field=condition.get('if_field', None),
                                                  state=condition.get('state', None),
                                                  condition=condition.get('condition', None),
                                                  field=condition.get('field', None),
                                                  value=condition.get('value', None),
                                                  customer_template=template)
                for index, item in enumerate(template_form):
                    insert_form_data(item=item, form=None, customer_template=template, index=index + 1)
            form.form_price = form_price
            if published_form:
                published_form.customer_form = form
            form.save()

            return Response({'message': 'Successfully submitted formdata', 'form_id': form.id, 'customer_id':
                request.user.id})

        raise Exception('You are an inactive user please verify Your email first')
    else:
        raise Exception('Form data is not available')

@api_view(['GET'])
def get_site_details(request):

    total_no_of_forms_admin = AdminFormModules.objects.filter().count()
    total_no_of_forms_customers = CustomerForms.objects.filter().count()
    total_forms = total_no_of_forms_admin + total_no_of_forms_customers
    total_no_of_organisations = CustomUser.objects.filter(organisation_id__isnull=False).count()
    total_no_of_customers = CustomUser.objects.filter(organisation_id__isnull=True, role_type='C').count()
    total_published_forms = CustomerForms.objects.filter(status='P').count()
    site_details = {
        'total_no_of_forms_customers': total_no_of_forms_customers,
        'total_no_of_forms_admin': total_no_of_forms_admin,
        'total_forms': total_forms,
        'total_no_of_customers': total_no_of_customers,
        'total_no_of_organisations': total_no_of_organisations,
        'total_published_forms': total_published_forms
    }
    return Response(site_details)

def get_template_data(template_data, templates=None, customer_template=None ):

    headers = HeaderField.objects.filter(form=templates, customer_template=customer_template).order_by(
        'step').values()
    if headers:
        for header in headers:
            header.update({'element': 'Header'})
            header.pop('id')
            header.pop('form_id')
            header.pop('customer_template_id')
            header.pop('help_text')
            header.pop('name')
            header['id'] = header.pop('field_id')
            header['required'] = header.pop('is_required')
            header['content'] = header.pop('placeholder')
            header['text'] = header.pop('label')
            template_data['form'].append(header)

    labels = LabelField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if labels:
        for label in labels:
            label.update({'element': 'Label'})
            label.pop('id')
            label.pop('form_id')
            label.pop('customer_template_id')
            label.pop('help_text')
            label.pop('name')
            label['id'] = label.pop('field_id')
            label['required'] = label.pop('is_required')
            label['content'] = label.pop('placeholder')
            label['text'] = label.pop('label')
            template_data['form'].append(label)

    linebreaks = LineBreakField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if linebreaks:
        for linebreak in linebreaks:
            linebreak.update({'element': 'LineBreak'})

            linebreak.pop('form_id')
            linebreak.pop('customer_template_id')
            linebreak.pop('help_text')
            linebreak.pop('name')
            linebreak['id'] = linebreak.pop('field_id')
            linebreak['required'] = linebreak.pop('is_required')
            #linebreak['content'] = linebreak.pop('placeholder')
            linebreak['text'] = linebreak.pop('label')
            template_data['form'].append(linebreak)

    checkboxes = SingleCheckBox.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if checkboxes:
        print checkboxes
        for checkbox in checkboxes:
            checkbox.update({'element': 'Checkboxes'})
            checkbox['check_id'] = checkbox.pop('id')
            checkbox.pop('form_id')

            checkbox.pop('customer_template_id')
            checkbox['id'] = checkbox.pop('field_id')
            checkbox['required'] = checkbox.pop('is_required')
            checkbox['field_name'] = checkbox.pop('name')
            #checkbox['content'] = checkbox.pop('placeholder')
            checkbox['text'] = checkbox.pop('help_text')
            checkbox['options'] = []
            options = Options.objects.filter(singlecheckbox_id=checkbox['check_id']).values('option_label',
                                                                                          'option_value',
                                                                                   'option_field_id','option_text','selected')
            for option in options:
                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                checkbox['options'].append(option)
            checkbox.pop('check_id')
            template_data['form'].append(checkbox)

    tags = Tags.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if tags:
        for tag in tags:
            tag.update({'element': 'Tags'})
            tag.pop('form_id')

            tag.pop('customer_template_id')
            tag['tag_id'] = tag.pop('id')
            tag['id'] = tag.pop('field_id')
            tag['required'] = tag.pop('is_required')
            tag['field_name'] = tag.pop('name')
            #tag['content'] = tag.pop('placeholder')
            tag['text'] = tag.pop('help_text')
            tag['options'] = []
            options = Options.objects.filter(tags_id=tag['tag_id']).values('option_label', 'option_value',
                                                                                   'option_field_id', 'option_text',
                                                                                   'selected')
            for option in options:
                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                tag['options'].append(option)
            tag.pop('tag_id')
            template_data['form'].append(tag)

    paragarphs = ParagraphField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if paragarphs:
        for paragraph in paragarphs:
            paragraph.update({'element': 'Paragraph'})
            paragraph.pop('id')

            paragraph.pop('form_id')
            paragraph.pop('customer_template_id')
            paragraph['id'] = paragraph.pop('field_id')
            paragraph['required'] = paragraph.pop('is_required')
            #paragraph['content'] = paragraph.pop('placeholder')
            paragraph['text'] = paragraph.pop('help_text')
            template_data['form'].append(paragraph)

    signatures = SignatureField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if signatures:
        for signature in signatures:
            signature.update({'element': 'Signature'})
            signature.pop('id')

            signature.pop('form_id')
            signature.pop('customer_template_id')
            signature['id'] = signature.pop('field_id')
            signature['required'] = signature.pop('is_required')
            signature.pop('placeholder')
            signature['text'] = signature.pop('help_text')
            signature['field_name'] = signature.pop('name')
            template_data['form'].append(signature)

    ranges = RangeField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if ranges:
        for rang in ranges:
            rang.update({'element': 'Range'})
            rang.pop('id')

            rang.pop('form_id')
            rang.pop('customer_template_id')
            rang['id'] = rang.pop('field_id')
            rang['required'] = rang.pop('is_required')
            rang['text'] = rang.pop('help_text')
            rang['field_name'] = rang.pop('name')
            template_data['form'].append(rang)

    radiobuttons = SingleRadioBox.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if radiobuttons:
        for radibutton in radiobuttons:
            radibutton.update({'element': 'RadioButtons'})
            radibutton.pop('form_id')

            radibutton.pop('customer_template_id')
            radibutton['radiobutton_id'] = radibutton.pop('id')
            radibutton['id'] = radibutton.pop('field_id')
            radibutton['required'] = radibutton.pop('is_required')
            radibutton['field_name'] = radibutton.pop('name')
            #radibutton['content'] = radibutton.pop('placeholder')
            radibutton['text'] = radibutton.pop('help_text')
            radibutton['options'] = []
            options = Options.objects.filter(singleradiobox_id=radibutton['radiobutton_id']).values('option_label',
                                                                                                  'option_value',
                                                                                     'option_field_id','option_text','selected')
            for option in options:

                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                radibutton['options'].append(option)
            radibutton.pop('radiobutton_id')
            template_data['form'].append(radibutton)

    textinputs = TextField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if textinputs:
        for textinput in textinputs:
            textinput.update({'element': 'TextInput'})
            textinput.pop('id')
            textinput.pop('form_id')

            textinput.pop('customer_template_id')
            textinput['id'] = textinput.pop('field_id')
            textinput['required'] = textinput.pop('is_required')
            textinput.pop('placeholder')
            textinput.pop('max_length')
            textinput['text'] = textinput.pop('help_text')
            textinput['field_name'] = textinput.pop('name')
            template_data['form'].append(textinput)

    numberinputs = NumberInput.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if numberinputs:
        for numberinput in numberinputs:
            numberinput.update({'element': 'NumberInput'})
            numberinput.pop('id')
            numberinput.pop('form_id')

            numberinput.pop('customer_template_id')
            numberinput['id'] = numberinput.pop('field_id')
            numberinput['required'] = numberinput.pop('is_required')
            numberinput.pop('placeholder')
            numberinput.pop('max_length')
            numberinput['text'] = numberinput.pop('help_text')
            numberinput['field_name'] = numberinput.pop('name')
            template_data['form'].append(numberinput)

    textareas = TextArea.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if textareas:
        for textarea in textareas:
            textarea.update({'element': 'TextArea'})
            textarea.pop('id')
            textarea.pop('form_id')

            textarea.pop('customer_template_id')
            textarea['id'] = textarea.pop('field_id')
            textarea['required'] = textarea.pop('is_required')
            textarea.pop('placeholder')
            textarea.pop('max_length')
            textarea['text'] = textarea.pop('help_text')
            textarea['field_name'] = textarea.pop('name')
            template_data['form'].append(textarea)

    images = ImageField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if images:
        for image in images:
            image.update({'element': 'Image'})
            image.pop('id')
            image.pop('form_id')

            image.pop('customer_template_id')
            image.pop('label')
            image['id'] = image.pop('field_id')
            image['required'] = image.pop('is_required')
            #image['content'] = image.pop('placeholder')
            image['text'] = image.pop('help_text')
            image['field_name'] = image.pop('name')
            template_data['form'].append(image)

    image_overlay = ImageOverlay.objects.filter(form=templates, customer_template=customer_template).order_by(
        'step').values()
    if image_overlay:
        for image in image_overlay:
            image.update({'element': 'ImageMarker'})
            image.pop('id')
            image.pop('form_id')

            image.pop('customer_template_id')
            image['id'] = image.pop('field_id')
            image['required'] = image.pop('is_required')
            # image['content'] = image.pop('placeholder')
            image['text'] = image.pop('help_text')
            image['field_name'] = image.pop('name')
            template_data['form'].append(image)

    ratings = RatingField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if ratings:
        for rating in ratings:
            rating.update({'element': 'Rating'})
            rating.pop('id')
            rating.pop('form_id')

            rating.pop('customer_template_id')
            rating['id'] = rating.pop('field_id')
            rating['required'] = rating.pop('is_required')
            #rating['content'] = rating.pop('placeholder')
            rating['text'] = rating.pop('help_text')
            rating['field_name'] = rating.pop('name')
            template_data['form'].append(rating)

    datefields = DateTimeField.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if datefields:
        for datefield in datefields:
            datefield.update({'element': 'DatePicker'})
            datefield.pop('id')
            datefield.pop('form_id')

            datefield.pop('customer_template_id')
            datefield['id'] = datefield.pop('field_id')
            datefield['required'] = datefield.pop('is_required')
            datefield.pop('placeholder')
            datefield['text'] = datefield.pop('help_text')
            datefield['field_name'] = datefield.pop('name')
            template_data['form'].append(datefield)

    dropdowns = DropDown.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if dropdowns:
        for dropdown in dropdowns:
            dropdown.update({'element': 'Dropdown'})
            dropdown.pop('form_id')

            dropdown.pop('customer_template_id')
            dropdown['dropdown_id'] = dropdown.pop('id')
            dropdown['id'] = dropdown.pop('field_id')
            dropdown['required'] = dropdown.pop('is_required')
            dropdown['field_name'] = dropdown.pop('name')
            #dropdown['content'] = dropdown.pop('placeholder')
            dropdown['text'] = dropdown.pop('help_text')
            dropdown['options'] = []
            options = Options.objects.filter(dropdown_id=dropdown['dropdown_id']).values('option_label', 'option_value',
                                                                             'option_field_id','option_text','selected')
            for option in options:

                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                dropdown['options'].append(option)
            dropdown.pop('dropdown_id')
            template_data['form'].append(dropdown)

    cameras = Camera.objects.filter(form=templates, customer_template=customer_template).order_by('step').values()
    if cameras:
        for camera in cameras:
            camera.update({'element': 'Camera'})
            camera.pop('id')
            camera.pop('form_id')

            camera.pop('customer_template_id')
            camera['id'] = camera.pop('field_id')
            camera['required'] = camera.pop('is_required')
            camera['text'] = camera.pop('help_text')
            camera['field_name'] = camera.pop('name')
            template_data['form'].append(camera)

@api_view(['POST'])
def update_passcode(request):

    passcode = request.data.get('passcode', None)
    user = request.user
    if user and passcode:
        user.passcode = passcode
        user.save()
        return Response({'user_id': request.user.id, 'passcode': user.passcode})
    else:
        return Response({'message': 'missing parameters'})

@api_view(['GET'])
def get_passcode(request):
    passcode = request.user.passcode
    return Response({'passcode': passcode})

@api_view(['POST'])
def confirm_passcode(request):

    data_code = request.data
    passcode = int(data_code.get('passcode', None))
    if passcode:
        user_email_domain = (request.user.email).split('@')[1]
        organisation_ob = Organisation.objects.filter(organisation_email__contains=user_email_domain)[0]
        organisation = CustomUser.objects.filter(organisation__id=organisation_ob.id, role_type='OA')[0]
        stored_passcode = int(organisation.passcode)
        if stored_passcode == passcode:
            return Response({'is_verified': True})
        else:
            return Response({'is_verified': False})

@api_view(['GET'])
def customer_form_listing(request):
    customer_id = int(request.query_params.get('customer_id', None))
    organisation_id = int(request.query_params.get('organisation_id', None))
    status = request.query_params.get('status', None)
    if customer_id:
        try:
            user = CustomUser.objects.get(id=customer_id)
        except(CustomUser.DoesNotExist):
            raise Exception({'message': 'User Does not exist'})
    if organisation_id:
        try:
            organisation = Organisation.objects.get(id=organisation_id)
        except(Organisation.DoesNotExist):
            raise Exception({'message': 'organisation does not exist'})
        users = organisation.customuser_set.filter()
        for user in users:
            if user.organisation.organistation_name:
                org = user
                break
            else:
                org = None
        user = CustomUser.objects.get(username=org)
    customer_forms = CustomerForms.objects.filter(user=user, status=status, is_deleted=False)
    # paginator = PageNumberPagination()
    # paginator.page_size = PAGE_SIZE
    # paginated_data = paginator.paginate_queryset(customer_forms, request)
    # serializer = CustomerFormSerializer(paginated_data, many=True)
    # return paginator.get_paginated_response(serializer.data)
    distinct_publish_ids = []
    # for form in customer_forms:
    #     print form
    #     if form['publish_id']:
    #         distinct_publish_ids.append(form['publish_id'])
    # distinct_publish_ids = list(set(distinct_publish_ids))
    # forms = CustomerForms.objects.filter(publish_id__in=distinct_publish_ids)
    serializer = CustomerFormSerializer(customer_forms, many=True)
    data = serializer.data
    for item in data:
        form_id = item.get('id', None)
        if form_id:
            try:
                CustomerForms.objects.get(id=form_id)
            except(CustomerForms.DoesNotExist):
                raise Exception('This Form id does not exist')
            encoded_form_id = ''.join(random.choice(ascii_letters) for i in range(20))
            token_ob = FormLinkToken.objects.create(token=encoded_form_id, user=user, form_id=form_id)
            expiration_time = datetime.datetime.strftime(datetime.datetime.now() + datetime.timedelta(days=2),
                                                         "%Y-%m-%d %H:%M:%S")
            # site = get_current_site(request)
            # link = "http://{}/{}".format(site, encoded_form_id)
            token_ob.key_expires = expiration_time
            token_ob.save()
            item.update({'form_link': encoded_form_id})
    return Response(data)

@api_view(['GET'])
def delete_customer_form(request):

    form_id = request.query_params.get('form_id')
    form = CustomerForms.objects.get(id=form_id)
    form.is_deleted = True
    form.save()
    return Response({'message': 'Form has been deleted', 'user_id': form.user.id})

@api_view(['GET'])
def generate_encoded_form_id(request):

    user = request.user
    form_id = request.query_params.get('form_id', None)
    if form_id:
        try:
            CustomerForms.objects.get(id=form_id)
        except(CustomerForms.DoesNotExist):
            raise Exception('This Form id does not exist')
        encoded_form_id = ''.join(random.choice(ascii_letters) for i in range(20))
        token_ob = FormLinkToken.objects.create(token=encoded_form_id, user=user, form_id=form_id)
        expiration_time = datetime.datetime.strftime(datetime.datetime.now() + datetime.timedelta(days=2), "%Y-%m-%d %H:%M:%S")
        # site = get_current_site(request)
        # link = "http://{}/{}".format(site, encoded_form_id)
        link = "{}".format(encoded_form_id)
        print link
        token_ob.key_expires = expiration_time
        token_ob.save()
        return Response({'form_link': link})
    else:
        return Response({'message': 'missing parameters'})

@api_view(['POST'])
@permission_classes((AllowAny, ))
def render_form_data_by_link(request):
    token = str(request.data.get('token', None))
    print "this is token string"
    print token
    current_time = datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S")
    curr_time = datetime.datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S" )
    try:
        token_ob = FormLinkToken.objects.get(token=token)
        print "this is token"
        print token_ob
    except:
        raise Exception('Your Token has been already used')
    expiration_time = token_ob.key_expires
    if token_ob:
        form_id = token_ob.form_id
        if curr_time > expiration_time:
            encoded_form_id = ''.join(random.choice(ascii_letters) for i in range(20))
            token_ob = FormLinkToken.objects.create(token=encoded_form_id, user=user, form_id=form_id)
            expiration_time = datetime.datetime.strftime(datetime.datetime.now() + datetime.timedelta(days=2),
                                                         "%Y-%m-%d %H:%M:%S")
            token_ob.key_expires = expiration_time
            token_ob.save()
            return Response({'message': 'Your token has been expired', 'refresh_token': encoded_form_id})
        #token_ob.delete()
        return view_customer_form(request, form_id)

@api_view(['GET'])
def list_functional_modules(request):

    data = {}
    welcomemodule = WelcomeModuleAdmin.objects.get()
    serializer = WelcomeModuleAdminSerializer(welcomemodule, context={'request': request})
    print "this is welcome module"
    print serializer.data
    data['welcomemodule'] = serializer.data
    submitmodule = SubmitModuleAdmin.objects.get()
    serializer = SubmitModuleAdminSerializer(submitmodule)
    data['submitmodule'] = serializer.data
    unlockmodule = UnlockModuleAdmin.objects.get()
    serializer = UnlockModuleAdminSerializer(unlockmodule)
    data['unlockmodule'] = serializer.data
    dropboxmodule = DropboxModuleAdmin.objects.get()
    serializer = DropboxModuleAdminSerializer(dropboxmodule)
    data['dropboxmodule'] = serializer.data

    emailmodule = EmailModuleAdmin.objects.get()
    serializer = EmailModuleAdminSerializer(emailmodule)
    data['emailmodule'] = serializer.data
    drivemodule = GoogleDriveModuleAdmin.objects.get()
    serializer = GoogleDriveModuleAdminSerializer(drivemodule)
    data['drivemodule'] = serializer.data
    return Response(data)

@permission_classes((AllowAny, ))
@api_view(['POST'])
@transaction.atomic
def submit_form_data(request):
    form_data = request.data
    print "this us form data"
    print form_data
    authorization_header = request.META.get('HTTP_AUTHORIZATION', None)
    device_token_header = request.META.get('HTTP_DEVICEID', None)
    if authorization_header:
        user = request.user
    else:
        user = None
    # if device_token_header:
    #     if Submittedforms.objects.filter(device_token=device_token_header).exists():
    #         raise Exception('Sorry, You have already Submitted the form')
    if form_data:
        customer_form_id = form_data.get('customer_form_id', None)
        template_data = form_data.get('form', None)
        user_data = form_data.get('user_data', None)
        print "this is user data"
        print user_data
        if customer_form_id:
            try:
                form = CustomerForms.objects.get(id=customer_form_id)
            except(CustomerForms.DoesNotExist):
                raise Exception('Form Does not exist')

            if user_data:
                print "in user data"
                user_data_ob = SubmitFormUser.objects.create(first_name=user_data['first_name'],
                                              last_name=user_data['last_name'],
                                              email=user_data.get('email', None),
                                              )
                print user_data_ob
            else:
                user_data_ob = None
            submitform = Submittedforms.objects.create(status='S',
                                                       published_customer_form=form,
                                                       user=user,
                                                       user_data=user_data_ob)
            submitform.title = form.title
            submitform.form_price = form.form_price
            if device_token_header:
                submitform.device_token = device_token_header
            submitform.save()
            for template in template_data:
                template_id = template.get('customer_template_id', None)
                template_ob = CustomerTemplates.objects.filter(id=template_id)
                if template_id:
                    template_elements = template.get('template', None)
                    for element in template_elements:
                        if element['element'] == 'Header':
                            print "Header"
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            header = HeaderField.objects.get(field_id=field_id, customer_template=template_ob[0])
                            header.submitform.add(submitform)
                            header.save()
                            if header:
                                HeaderFieldData.objects.create(header=header,
                                                              submitform=submitform,
                                                              customer_form=form,
                                                              input_data=input_data,
                                                              input_data_text=input_data_text)

                        if element['element'] == 'Label':
                            print "label"
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            label = LabelField.objects.get(field_id=field_id, customer_template=template_ob[0])
                            label.submitform.add(submitform)
                            label.save()
                            if label:
                                LabelFieldData.objects.create(labelfield=label,
                                                              submitform=submitform,
                                                              customer_form=form,
                                                              input_data=input_data,
                                                              input_data_text=input_data_text)

                        if element['element'] == 'Checkboxes':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            checkbox = SingleCheckBox.objects.get(field_id=field_id, customer_template=template_ob[0])
                            checkbox.submitform.add(submitform)
                            checkbox.save()
                            if checkbox:
                                SingleCheckBoxData.objects.create(singlecheckbox=checkbox,
                                                              submitform=submitform,
                                                              customer_form=form,
                                                              input_data=input_data,
                                                                  input_data_text=input_data_text)

                        if element['element'] == 'Paragraph':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            paragraph = ParagraphField.objects.get(field_id=field_id, customer_template=template_ob[0])
                            paragraph.submitform.add(submitform)
                            paragraph.save()
                            if paragraph:
                                ParagraphFieldData.objects.create(paragraphfield=paragraph,
                                                              submitform=submitform,
                                                              customer_form=form,
                                                              input_data=input_data,
                                                                  input_data_text=input_data_text)

                        if element['element'] == 'Signature':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            signature = SignatureField.objects.get(field_id=field_id, customer_template=template_ob[0])
                            signature.submitform.add(submitform)
                            signature.save()
                            if signature:
                                SignatureFieldData.objects.create(signaturefield=signature,
                                                              submitform=submitform,
                                                              customer_form=form,
                                                              input_data=input_data,
                                                                  input_data_text=input_data_text)

                        if element['element'] == 'RadioButtons':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            radiobutton = SingleRadioBox.objects.get(field_id=field_id,
                                                                     customer_template=template_ob[0])
                            radiobutton.submitform.add(submitform)
                            radiobutton.save()
                            if radiobutton:
                                SingleRadioBoxData.objects.create(listradiobox=radiobutton,
                                                              submitform=submitform,
                                                              customer_form=form,
                                                              input_data=input_data,
                                                                  input_data_text=input_data_text)

                        if element['element'] == 'TextInput':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            textinput = TextField.objects.get(field_id=field_id, customer_template=template_ob[0])
                            textinput.submitform.add(submitform)
                            textinput.save()
                            if textinput:
                                TextFieldData.objects.create(textfield=textinput,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                             input_data_text=input_data_text)
                        if element['element'] == 'NumberInput':

                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            numberinput = NumberInput.objects.get(field_id=field_id,
                                                                     customer_template=template_ob[0])
                            numberinput.submitform.add(submitform)
                            numberinput.save()
                            if numberinput:
                                NumberInputData.objects.create(numberinput=numberinput,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                               input_data_text=input_data_text)

                        if element['element'] == 'TextArea':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            textarea = TextArea.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])
                            textarea.submitform.add(submitform)
                            textarea.save()
                            if textarea:
                                TextAreaData.objects.create(textarea=textarea,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                            input_data_text=input_data_text)

                        if element['element'] == 'Range':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            rang = RangeField.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])
                            rang.submitform.add(submitform)
                            rang.save()
                            if rang:
                                RangeFieldData.objects.create(rangefield=rang,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                              input_data_text=input_data_text)

                        if element['element'] == 'Camera':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            camera = Camera.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])

                            camera.submitform.add(submitform)
                            camera.save()
                            if camera:
                                CameraData.objects.create(camera=camera,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                          input_data_text=input_data_text)

                        if element['element'] == 'Rating':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            rating = RatingField.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])
                            rating.submitform.add(submitform)
                            rating.save()
                            if rating:
                                RatingFieldData.objects.create(rating=rating,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                               input_data_text=input_data_text)

                        if element['element'] == 'Image':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            image = ImageField.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])

                            image.submitform.add(submitform)
                            image.save()
                            if image:
                                ImageFieldData.objects.create(image=image,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                              input_data_text=input_data_text)

                        if element['element'] == 'DatePicker':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            datepicker = DateTimeField.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])
                            datepicker.submitform.add(submitform)
                            datepicker.save()
                            if datepicker:
                                DateTimeFieldData.objects.create(datefield=datepicker,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                                 input_data_text=input_data_text
                                                                 )

                        if element['element'] == 'Dropdown':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            print input_data
                            dropdown = DropDown.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])

                            dropdown.submitform.add(submitform)
                            dropdown.save()

                            if dropdown:
                                DropDownData.objects.create(dropdown=dropdown,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                            input_data_text=input_data_text
                                                            )

                        if element['element'] == 'Tags':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            tag = Tags.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])

                            tag.submitform.add(submitform)
                            tag.save()
                            if tag:
                                TagsData.objects.create(tag=tag,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                        input_data_text=input_data_text)

                        if element['element'] == 'ImageMarker':
                            field_id = element.get('field_id', None)
                            input_data = element.get('input_data', None)
                            input_data_text = element.get('input_data_text', None)
                            image_overlay = ImageOverlay.objects.get(field_id=field_id,
                                                                  customer_template=template_ob[0])

                            image_overlay.submitform.add(submitform)
                            image_overlay.save()
                            if image_overlay:
                                ImageOverlayData.objects.create(imageoverlay=image_overlay,
                                                                  submitform=submitform,
                                                                  customer_form=form,
                                                                  input_data=input_data,
                                                                input_data_text=input_data_text)

            create_pdf.apply_async((form_data, submitform.id, ))
            print "Form Submitted finally"
            print submitform.id
            return Response({'message': 'Form Data Submitted Successfully', 'submit_form_id': submitform.id})


@api_view(['POST'])
def get_submit_form_data(request):

    submit_form_id = request.query_params.get('submit_form_id', None)
    submit_form_id = int(submit_form_id)
    try:
        submitform = Submittedforms.objects.get(id=submit_form_id)
    except(Submittedforms.DoesNotExist):
        raise Exception('Submitted Form Does Not Exist')
    form_id = submitform.published_customer_form.id
    #submitted_data_dict = OrderedDict()
    try:
        customer_form = CustomerForms.objects.get(id=form_id)
        print customer_form
    except(CustomerForms.DoesNotExist):
        raise Exception('Form does not exist')

    submit_form_data = OrderedDict()
    submit_form_data['title'] = submitform.title
    submit_form_data['customer_form_id'] = form_id
    submit_form_data['status'] = submitform.status
    submit_form_data['description'] = customer_form.description
    submit_form_data['form_price'] = submitform.form_price
    submit_form_data['customer_form'] = []
    submit_form_data['user_data'] = {}
    data = dict()
    if submitform.user_data:
        data['first_name'] = submitform.user_data.first_name
        data.update({
                      'last_name': submitform.user_data.last_name,
                      'email': submitform.user_data.email}
        )
    print "this is user data"
    print data
    submit_form_data['user_data'] = data
    submit_form_data['functional_modules'] = []
    all_welcome_modules = WelcomeModuleCustomer.objects.filter(customer_form=customer_form)
    if all_welcome_modules:
        for welcomemodule in all_welcome_modules:
            print welcomemodule
            welcomemodule_data = {}
            welcomemodule_data.update({'type': 'welcomemodule'})
            welcomemodule_data['data'] = []
            serializer = WelcomeModuleCustomerSerializer(welcomemodule, context={'request': request})
            welcomemodule_data['data'].append(serializer.data)
            submit_form_data['functional_modules'].append(welcomemodule_data)

    all_submit_modules = SubmitModuleCustomer.objects.filter(customer_form=customer_form)
    if all_submit_modules:
        for submitmodule in all_submit_modules:
            submitmodule_data = {}
            submitmodule_data.update({'type': 'submitmodule'})
            submitmodule_data['data'] = []
            data_dict = {}
            data_dict['message'] = submitmodule.message
            data_dict['module_price'] = submitmodule.module_price
            data_dict['cfm_id'] = submitmodule.id
            submitmodule_data['data'].append(data_dict)
            submit_form_data['functional_modules'].append(submitmodule_data)
    all_unlock_modules = UnlockModuleCustomer.objects.filter(customer_form=customer_form)
    if all_unlock_modules:
        for unlockmodule in all_unlock_modules:
            unlockmodule_data = {}
            unlockmodule_data.update({'type': 'unlockmodule'})
            data_dict = {}
            unlockmodule_data['data'] = []
            data_dict['message'] = unlockmodule.message
            data_dict['module_price'] = unlockmodule.module_price
            data_dict['cfm_id'] = unlockmodule.id
            unlockmodule_data['data'].append(data_dict)
            submit_form_data['functional_modules'].append(unlockmodule_data)
    all_dropbox_modules = DropboxModuleCustomer.objects.filter(customer_form=customer_form)
    if all_dropbox_modules:
        for dropboxmodule in all_submit_modules:
            dropboxmodule_data = {}
            dropboxmodule_data.update({'type': 'dropboxmodule'})
            data_dict = {}
            dropboxmodule_data['data'] = []
            data_dict['module_price'] = dropboxmodule.module_price
            data_dict['cfm_id'] = dropboxmodule.id
            dropboxmodule_data['data'].append(data_dict)
            submit_form_data['functional_modules'].append(dropboxmodule_data)

    all_email_modules = EmailModuleCustomer.objects.filter(customer_form=customer_form)
    if all_email_modules:
        for emailmodule in all_email_modules:
            emailmodule_data = {}
            emailmodule_data.update({'type': 'emailmodule'})
            data_dict = {}
            emailmodule_data['data'] = []
            data_dict['module_price'] = emailmodule.module_price
            data_dict['cfm_id'] = emailmodule.id
            emailmodule_data['data'].append(data_dict)
            submit_form_data['functional_modules'].append(emailmodule_data)

    all_drive_modules = GoogleDriveModuleCustomer.objects.filter(customer_form=customer_form)
    if all_drive_modules:
        for drivemodule in all_submit_modules:
            drivemodule_data = {}
            drivemodule_data.update({'type': 'drivemodule'})
            data_dict = {}
            drivemodule_data['data'] = []
            data_dict['module_price'] = drivemodule.module_price
            data_dict['cfm_id'] = drivemodule.id
            drivemodule_data['data'].append(data_dict)
            submit_form_data['functional_modules'].append(drivemodule_data)

    form_templates = CustomerTemplates.objects.filter(customer_form=customer_form)
    # template_data['form_conditions'] = []
    # conditions_in_form = Conditions.objects.filter(form=template).values('if_field', 'state', 'condition', 'field',
    #                                                                      'value')
    # for condition in conditions_in_form:
    #     template_data['form_conditions'].append(condition)
    for template in form_templates:

        template_data = OrderedDict()
        template_data['title'] = template.title
        template_data['customertemplate_id'] = template.id
        template_data['description'] = template.description
        template_data['module_price'] = template.module_price
        template_data['min'] = template.min
        template_data['max'] = template.max
        template_data['form'] = []
        template_data['form_conditions'] = []
        conditions_in_form = Conditions.objects.filter(customer_template=template).values('if_field', 'state',
                                                                                          'condition', 'field',
                                                                                          'value')
        for condition in conditions_in_form:
            template_data['form_conditions'].append(condition)
        print "going into get template data"
        get_template_data_for_submit_form(template_data, customer_template=template, submit_form=submitform)
        print "returned"
        # groups_in_form = InputGroup.objects.filter(form=form_id)
        # for group in groups_in_form:
        #     group_info = get_template_groups(template_data, group)
        #     template_data['form'].append(group_info)
        sorted_template_data = sorted(template_data['form'], key=itemgetter('step'))
        print "this is sorted template data"
        print sorted_template_data
        template_data['form'] = sorted_template_data
        for item in sorted_template_data:
            item.pop('step')
        print "SORTED"
        submit_form_data['customer_form'].append(template_data)

    return Response(submit_form_data)


def get_template_data_for_submit_form(template_data, customer_template=None, submit_form=None):

    headers = HeaderField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    print "these are headers"
    print headers
    if headers:
        for header in headers:
            print "this is header"
            print header
            input_data = HeaderFieldData.objects.filter(submitform=submit_form, header=HeaderField.objects.get(
                id=header['id'])).values('input_data', 'input_data_text')
            print "this is input data"
            print input_data
            header.update({'element': 'Header'})
            if input_data:
                header.update(input_data[0])
            header.pop('id')
            header.pop('form_id')
            header.pop('customer_template_id')
            header.pop('help_text')
            header.pop('name')
            header['id'] = header.pop('field_id')
            header['required'] = header.pop('is_required')
            header['content'] = header.pop('placeholder')
            header['text'] = header.pop('label')
            template_data['form'].append(header)

    labels = LabelField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by('step').values()
    if labels:
        for label in labels:
            input_data = LabelFieldData.objects.filter(submitform=submit_form, labelfield=LabelField.objects.get(
                id=label['id'])).values('input_data', 'input_data_text')
            label.update({'element': 'Label'})
            label.update(input_data[0])
            label.pop('id')
            label.pop('form_id')
            label.pop('customer_template_id')
            label.pop('help_text')
            label.pop('name')
            label['id'] = label.pop('field_id')
            label['required'] = label.pop('is_required')
            label['content'] = label.pop('placeholder')
            label['text'] = label.pop('label')
            template_data['form'].append(label)

    linebreaks = LineBreakField.objects.filter(customer_template=customer_template).order_by('step').values()
    if linebreaks:
        for linebreak in linebreaks:
            linebreak.update({'element': 'LineBreak'})

            linebreak.pop('form_id')
            linebreak.pop('customer_template_id')
            linebreak.pop('help_text')
            linebreak.pop('name')
            linebreak['id'] = linebreak.pop('field_id')
            linebreak['required'] = linebreak.pop('is_required')
            #linebreak['content'] = linebreak.pop('placeholder')
            linebreak['text'] = linebreak.pop('label')
            template_data['form'].append(linebreak)

    checkboxes = SingleCheckBox.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if checkboxes:
        print checkboxes
        for checkbox in checkboxes:
            input_data = SingleCheckBoxData.objects.filter(submitform=submit_form, singlecheckbox=SingleCheckBox.objects.get(
                id=checkbox['id'])).values('input_data', 'input_data_text')
            print "these are input data"
            print input_data
            checkbox.update({'element': 'Checkboxes'})
            checkbox.update(input_data[0])
            checkbox['check_id'] = checkbox.pop('id')
            checkbox.pop('form_id')

            checkbox.pop('customer_template_id')
            checkbox['id'] = checkbox.pop('field_id')
            checkbox['required'] = checkbox.pop('is_required')
            checkbox['field_name'] = checkbox.pop('name')
            #checkbox['content'] = checkbox.pop('placeholder')
            checkbox['text'] = checkbox.pop('help_text')
            checkbox['options'] = []
            options = Options.objects.filter(singlecheckbox_id=checkbox['check_id']).values('option_label',
                                                                                          'option_value',
                                                                                   'option_field_id','option_text','selected')
            for option in options:
                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                checkbox['options'].append(option)
            checkbox.pop('check_id')
            template_data['form'].append(checkbox)

    tags = Tags.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by('step').values()
    if tags:
        for tag in tags:
            input_data = TagsData.objects.filter(submitform=submit_form, tag=Tags.objects.get(
                id=tag['id'])).values('input_data', 'input_data_text')
            tag.update({'element': 'Tags'})
            tag.pop('form_id')
            tag.update(input_data[0])
            tag.pop('customer_template_id')
            tag['tag_id'] = tag.pop('id')
            tag['id'] = tag.pop('field_id')
            tag['required'] = tag.pop('is_required')
            tag['field_name'] = tag.pop('name')
            #tag['content'] = tag.pop('placeholder')
            tag['text'] = tag.pop('help_text')
            tag['options'] = []
            options = Options.objects.filter(tags_id=tag['tag_id']).values('option_label', 'option_value',
                                                                                   'option_field_id', 'option_text',
                                                                                   'selected')
            for option in options:
                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                tag['options'].append(option)
            tag.pop('tag_id')
            template_data['form'].append(tag)

    paragarphs = ParagraphField.objects.filter(customer_template=customer_template,
                                               submitform__id=submit_form.id).order_by(
        'step').values()
    if paragarphs:
        for paragraph in paragarphs:
            input_data = ParagraphFieldData.objects.filter(submitform=submit_form, paragraphfield=ParagraphField.objects.get(
                id=paragraph['id'])).values('input_data', 'input_data_text')
            paragraph.update({'element': 'Paragraph'})
            paragraph.pop('id')
            paragraph.update(input_data[0])
            paragraph.pop('form_id')
            paragraph.pop('customer_template_id')
            paragraph['id'] = paragraph.pop('field_id')
            paragraph['required'] = paragraph.pop('is_required')
            #paragraph['content'] = paragraph.pop('placeholder')
            paragraph['text'] = paragraph.pop('help_text')
            template_data['form'].append(paragraph)

    signatures = SignatureField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if signatures:
        for signature in signatures:
            print 'signature'
            print signature
            print input_data
            input_data = SignatureFieldData.objects.filter(submitform=submit_form, signaturefield=SignatureField.objects.get(
                id=signature['id'])).values('input_data', 'input_data_text')
            signature.update({'element': 'Signature'})
            signature.pop('id')
            signature.pop('form_id')
            signature.update(input_data[0])
            signature.pop('customer_template_id')
            signature['id'] = signature.pop('field_id')
            signature['required'] = signature.pop('is_required')
            signature.pop('placeholder')
            signature['text'] = signature.pop('help_text')
            signature['field_name'] = signature.pop('name')
            template_data['form'].append(signature)

    ranges = RangeField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by('step').values()
    if ranges:
        for rang in ranges:
            input_data = RangeFieldData.objects.filter(submitform=submit_form, rangefield=RangeField.objects.get(
                id=rang['id'])).values('input_data', 'input_data_text')
            rang.update({'element': 'Range'})
            rang.pop('id')

            rang.update(input_data[0])
            rang.pop('form_id')
            rang.pop('customer_template_id')
            rang['id'] = rang.pop('field_id')
            rang['required'] = rang.pop('is_required')
            rang['text'] = rang.pop('help_text')
            rang['field_name'] = rang.pop('name')
            template_data['form'].append(rang)

    radiobuttons = SingleRadioBox.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if radiobuttons:
        for radibutton in radiobuttons:
            print radibutton
            input_data = SingleRadioBoxData.objects.filter(submitform=submit_form,
                                                           listradiobox=SingleRadioBox.objects.get(id=radibutton['id']
                                                                                                   )).values('input_data', 'input_data_text')
            print input_data
            radibutton.update({'element': 'RadioButtons'})
            radibutton.update(input_data[0])
            radibutton.pop('form_id')

            radibutton.pop('customer_template_id')
            radibutton['radiobutton_id'] = radibutton.pop('id')
            print radibutton['radiobutton_id']
            radibutton['id'] = radibutton.pop('field_id')
            radibutton['required'] = radibutton.pop('is_required')
            radibutton['field_name'] = radibutton.pop('name')
            #radibutton['content'] = radibutton.pop('placeholder')
            radibutton['text'] = radibutton.pop('help_text')
            radibutton['options'] = []
            options = Options.objects.filter(singleradiobox_id=radibutton['radiobutton_id']).values('option_label',
                                                                                                  'option_value',
                                                                                     'option_field_id','option_text','selected')
            for option in options:

                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                radibutton['options'].append(option)
            radibutton.pop('radiobutton_id')
            template_data['form'].append(radibutton)

    textinputs = TextField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if textinputs:
        for textinput in textinputs:
            input_data = TextFieldData.objects.filter(submitform=submit_form, textfield=TextField.objects.get(
                id=textinput['id'])).values('input_data', 'input_data_text')
            textinput.update({'element': 'TextInput'})
            textinput.pop('id')
            textinput.update(input_data[0])
            textinput.pop('form_id')

            textinput.pop('customer_template_id')
            textinput['id'] = textinput.pop('field_id')
            textinput['required'] = textinput.pop('is_required')
            textinput.pop('placeholder')
            textinput.pop('max_length')
            textinput['text'] = textinput.pop('help_text')
            textinput['field_name'] = textinput.pop('name')
            template_data['form'].append(textinput)

    numberinputs = NumberInput.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if numberinputs:
        for numberinput in numberinputs:
            input_data = NumberInputData.objects.filter(submitform=submit_form, numberinput=NumberInput.objects.get(
                id=numberinput['id'])).values('input_data', 'input_data_text')
            numberinput.update({'element': 'NumberInput'})
            numberinput.pop('id')
            numberinput.pop('form_id')
            numberinput.update(input_data[0])

            numberinput.pop('customer_template_id')
            numberinput['id'] = numberinput.pop('field_id')
            numberinput['required'] = numberinput.pop('is_required')
            numberinput.pop('placeholder')
            numberinput.pop('max_length')
            numberinput['text'] = numberinput.pop('help_text')
            numberinput['field_name'] = numberinput.pop('name')
            template_data['form'].append(numberinput)

    textareas = TextArea.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if textareas:
        print textareas
        for textarea in textareas:
            input_data = TextAreaData.objects.filter(submitform=submit_form, textarea=TextArea.objects.get(
                id=textarea['id'])).values('input_data', 'input_data_text')
            textarea.update({'element': 'TextArea'})
            textarea.pop('id')
            textarea.pop('form_id')
            textarea.update(input_data[0])
            textarea.pop('customer_template_id')
            textarea['id'] = textarea.pop('field_id')
            textarea['required'] = textarea.pop('is_required')
            textarea.pop('placeholder')
            textarea.pop('max_length')
            textarea['text'] = textarea.pop('help_text')
            textarea['field_name'] = textarea.pop('name')
            template_data['form'].append(textarea)

    images = ImageField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by('step').values()
    if images:
        print images
        for image in images:
            input_data = ImageFieldData.objects.filter(submitform=submit_form, image=ImageField.objects.get(
                id=image['id'])).values('input_data', 'input_data_text')
            image.update({'element': 'Image'})
            image.pop('id')
            image.pop('form_id')
            image.update(input_data[0])
            image.pop('customer_template_id')
            image.pop('label')
            image['id'] = image.pop('field_id')
            image['required'] = image.pop('is_required')
            #image['content'] = image.pop('placeholder')
            image['text'] = image.pop('help_text')
            image['field_name'] = image.pop('name')
            template_data['form'].append(image)

    image_overlay = ImageOverlay.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if image_overlay:
        for image in image_overlay:
            print image
            # image = ImageOverlay.objects.get(field_id=image['field_id'],created_on=image['created_on'],)
            input_data = ImageOverlayData.objects.filter(submitform=submit_form, imageoverlay=ImageOverlay.objects.get(
                id=image['id'])).values('input_data', 'input_data_text')
            image.update({'element': 'ImageMarker'})
            image.pop('id')
            image.pop('form_id')
            image.update(input_data[0])

            image.pop('customer_template_id')
            image['id'] = image.pop('field_id')
            image['required'] = image.pop('is_required')
            # image['content'] = image.pop('placeholder')
            image['text'] = image.pop('help_text')
            image['field_name'] = image.pop('name')
            template_data['form'].append(image)

    ratings = RatingField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    print ratings
    if ratings:
        print 'ratings'
        for rating in ratings:
            input_data = RatingFieldData.objects.filter(submitform=submit_form, rating=RatingField.objects.get(
                id=rating['id'])).values('input_data', 'input_data_text')
            rating.update({'element': 'Rating'})
            rating.pop('id')
            rating.pop('form_id')
            rating.update(input_data[0])
            rating.pop('customer_template_id')
            rating['id'] = rating.pop('field_id')
            rating['required'] = rating.pop('is_required')
            #rating['content'] = rating.pop('placeholder')
            rating['text'] = rating.pop('help_text')
            rating['field_name'] = rating.pop('name')
            template_data['form'].append(rating)

    datefields = DateTimeField.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if datefields:
        print 'datepicker'
        for datefield in datefields:
            input_data = DateTimeFieldData.objects.filter(submitform=submit_form, datefield=DateTimeField.objects.get(
                id=datefield['id'])).values('input_data', 'input_data_text')
            datefield.update({'element': 'DatePicker'})
            datefield.pop('id')
            datefield.pop('form_id')
            datefield.update(input_data[0])
            datefield.pop('customer_template_id')
            datefield['id'] = datefield.pop('field_id')
            datefield['required'] = datefield.pop('is_required')
            datefield.pop('placeholder')
            datefield['text'] = datefield.pop('help_text')
            datefield['field_name'] = datefield.pop('name')
            template_data['form'].append(datefield)

    dropdowns = DropDown.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by(
        'step').values()
    if dropdowns:
        print 'dropdown'
        for dropdown in dropdowns:
            input_data = DropDownData.objects.filter(submitform=submit_form, dropdown=DropDown.objects.get(
                id=dropdown['id'])).values('input_data', 'input_data_text')
            dropdown.update({'element': 'Dropdown'})
            dropdown.pop('form_id')
            dropdown.update(input_data[0])
            dropdown.pop('customer_template_id')
            dropdown['dropdown_id'] = dropdown.pop('id')
            dropdown['id'] = dropdown.pop('field_id')
            dropdown['required'] = dropdown.pop('is_required')
            dropdown['field_name'] = dropdown.pop('name')
            #dropdown['content'] = dropdown.pop('placeholder')
            dropdown['text'] = dropdown.pop('help_text')
            dropdown['options'] = []
            options = Options.objects.filter(dropdown_id=dropdown['dropdown_id']).values('option_label', 'option_value',
                                                                             'option_field_id','option_text','selected')
            for option in options:

                option['key'] = option.pop('option_field_id')
                option['value'] = option.pop('option_value')
                option['text'] = option.pop('option_text')
                option.pop('selected')
                option.pop('option_label')
                dropdown['options'].append(option)
            dropdown.pop('dropdown_id')
            template_data['form'].append(dropdown)

    cameras = Camera.objects.filter(customer_template=customer_template, submitform__id=submit_form.id).order_by('step').values()
    if cameras:
        print 'camera'
        for camera in cameras:
            input_data = CameraData.objects.filter(submitform=submit_form, camera=Camera.objects.get(
                id=camera['id'])).values('input_data', 'input_data_text')
            camera.update({'element': 'Camera'})
            camera.pop('id')
            camera.pop('form_id')
            camera.update(input_data[0])
            camera.pop('customer_template_id')
            camera['id'] = camera.pop('field_id')
            camera['required'] = camera.pop('is_required')
            camera['text'] = camera.pop('help_text')
            camera['field_name'] = camera.pop('name')
            template_data['form'].append(camera)

@api_view(['POST'])
def change_status_to_submit(request):
    data = request.data
    if data:
        status = data.get('status', None)
        published_customer_form = data.get('published_customer_form', None)
        user = request.user
        try:
            published_customer_form = CustomerForms.objects.get(id=published_customer_form)
        except(CustomerForms.DoesNotExist):
            return Response({'message': 'Form does not exist'})
        Submittedforms.objects.create(status=status,
                                             published_customer_form=published_customer_form,
                                             user=user)
        return Response({'message': 'Status Changed Successfully'})


@api_view(['GET'])
def get_submitted_forms(request):
    authorization_header = request.META.get('HTTP_AUTHORIZATION', None)
    device_token_header = request.META.get('HTTP_DEVICEID', None)
    if authorization_header:
        user = request.user
        all_submitted_forms = Submittedforms.objects.filter(user=user)
    else:
        user = None
        all_submitted_forms = Submittedforms.objects.filter(user=user, device_token=device_token_header)
    paginator = PageNumberPagination()
    paginator.page_size = PAGE_SIZE
    total_pages = paginator.django_paginator_class(all_submitted_forms, PAGE_SIZE).num_pages
    paginated_data = paginator.paginate_queryset(sorted(all_submitted_forms, key=attrgetter('created_on'),
                                                        reverse=True), request)
    serializer = SubmittedFormSerializer(paginated_data, many=True)
    paginated_data_final = dict(paginator.get_paginated_response(serializer.data).data)
    paginated_data_final['total_pages'] = total_pages
    return Response(paginated_data_final)

@api_view(['GET'])
def no_of_users_in_a_date_range(request):

    from_date = request.query_params.get('from_date', None)
    to_date = request.query_params.get('to_date', None)
    if not from_date:
        raise Exception('Invalid Date Range')
    if not to_date:
        to_date = datetime.datetime.now().strftime("%Y-%m-%d")
    try:
        datetime.datetime.strptime(from_date, "%Y-%m-%d")
    except ValueError as e:
        raise ValueError({'mesage': e.message})
    try:
        datetime.datetime.strptime(to_date, "%Y-%m-%d")
    except ValueError:
        raise ValueError('Incorrect Date format it should be in format YYYY-mm-dd')

    all_users = CustomUser.objects.filter(date_joined__gte=from_date, date_joined__lte=to_date).order_by(
        '-date_joined').values('username', 'first_name', 'last_name', 'date_joined', 'email')
    if not all_users:
        return Response({'message': 'No Users in this range'})
    all_users_data = []
    for user in all_users:
        user['date_joined'] = user['date_joined'].strftime('%Y-%m-%d')
        all_users_data.append(user.values())
    table_headers = ['UserName', 'FirstName', 'LastName', 'Email', 'CreatedAt']
    all_users_data.insert(0, table_headers)
    doc = SimpleDocTemplate("test_report_lab.pdf", pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30,
                            bottomMargin=18)
    doc.pagesize = landscape(A4)
    elements = []

    data = all_users_data

    # TODO: Get this line right instead of just copying it from the docs
    style = TableStyle([('ALIGN', (1, 1), (-2, -2), 'RIGHT'),
                        ('TEXTCOLOR', (1, 1), (-2, -2), colors.red),
                        ('VALIGN', (0, 0), (0, -1), 'TOP'),
                        ('TEXTCOLOR', (0, 0), (0, -1), colors.blue),
                        ('ALIGN', (0, -1), (-1, -1), 'CENTER'),
                        ('VALIGN', (0, -1), (-1, -1), 'MIDDLE'),
                        ('TEXTCOLOR', (0, -1), (-1, -1), colors.green),
                        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                        ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                        ])

    # Configure style and word wrap
    s = getSampleStyleSheet()
    s = s["BodyText"]
    s.wordWrap = 'CJK'
    data2 = [[Paragraph(cell, s) for cell in row] for row in data]
    t = Table(data2)
    t.setStyle(style)

    # Send the data and build the file
    elements.append(t)
    doc.build(elements)
    from django.core.files import File
    pdf_file = open("/home/startxlabs/StartxLabs/eforms_project/eforms/test_report_lab.pdf", 'rb')
    print File(pdf_file)
    response = Response(
                        File(pdf_file),
                        content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="sample.pdf"'
    return response

@api_view(['GET'])
def get_organisation_published_forms():
    pass

@api_view(['POST'])
def upload_image_form_submit(request):
    data = request.data
    print data
    serializer = ImageUploadSerializer(data=data, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)

@api_view(['GET'])
def get_all_filled_forms_from_published_forms(request):

    user = request.user
    publish_form_id = request.query_params.get('publish_form_id', None)
    if publish_form_id:
        published_customer_form = CustomerForms.objects.get(id=publish_form_id)
        filled_forms = Submittedforms.objects.filter(published_customer_form=published_customer_form)
        if filled_forms:
            # paginator = PageNumberPagination()
            # paginator.page_size = PAGE_SIZE
            # paginated_data = paginator.paginate_queryset(filled_forms, request)
            # serializer = SubmittedFormSerializer(paginated_data, many=True)
            # return paginator.get_paginated_response(serializer.data)
            serializer = SubmittedFormSerializer(filled_forms, many=True)
            return Response(serializer.data)
        else:
            return Response({'message': 'No filled forms for this published form'})

    else:
        raise Exception('Query Parameter publish_form_id is missing')

@api_view(['GET'])
def make_payment(request):

    return_url = str((get_current_site(request).domain)[:-1] + reverse('exec_payment'))
    print return_url
    payment = Payment({
          "intent": "sale",
          "payer": {
          "payment_method": "paypal"
          },
        "redirect_urls": {
            "return_url": return_url,
            "cancel_url": "http://192.168.0.125:8000"
        },
          "transactions": [
          {
            "amount": {
            "total": "30.11",
            "currency": "INR",
            "details": {
                "subtotal": "30.00",
              "tax": "0.07",
              "shipping": "0.03",
              "handling_fee": "1.00",
              "shipping_discount": "-1.00",
              "insurance": "0.01"
            }
            },
            "description": "This is the payment transaction description.",
            # "custom": "EBAY_EMS_90048630024435",
            # "invoice_number": "4878758967312",
            "payment_options": {
            "allowed_payment_method": "INSTANT_FUNDING_SOURCE"
            },
            "soft_descriptor": "ECHI5786786",
            "item_list": {
            "items": [
              {
              "name": "hat",
              "description": "Brown color hat",
              "quantity": "5",
              "price": "3",
              "tax": "0.01",
              "sku": "1",
              "currency": "INR"
              },
              {
              "name": "handbag",
              "description": "Black color hand bag",
              "quantity": "1",
              "price": "15",
              "tax": "0.02",
              "sku": "product34",
              "currency": "INR"
              }
            ],
            "shipping_address": {
              "recipient_name": "Hello World",
              "line1": "Birhana Road",
              "line2": "unit#34",
              "city": "Kanpur",
               "country_code": "IN",
              "postal_code": "208001",
              "phone": "011862212345678",
              "state": "CA"
            }
            }
          }
          ],
          "note_to_payer": "Contact us for any questions on your order.",
        })
    settings.PAYMENT_OB = payment
    if payment.create():
        # Extract redirect url
        for link in payment.links:
            print link
            if link.method == "REDIRECT":
                # Capture redirect url
                redirect_url = str(link.href)
                return redirect(redirect_url)
    else:
        print("Error while creating payment:")
        print(payment.error)

@api_view(['GET'])
def execute_payment(request):
    user = request.user
    print request.query_params
    payment_id = request.query_params.get('paymentId', None)
    payer_id = request.query_params.get('PayerID', None)
    token = request.query_params.get('token', None)
    if payment_id:
        payment = Payment.find(payment_id)

    # Execute payment using payer_id obtained when creating the payment (following redirect)
    if payment.execute({"payer_id": payer_id}):
        user.is_paid_user = True
        user.is_trial_on = False
        user.save()
        return redirect('http://192.168.0.118:8002/dashboard/welcome/')
        #return render(request, template_name='confirm.html')
    else:
        raise Exception(payment.error)

@api_view(['GET'])
def update_paid_or_trial_of_a_user(request):

    user = request.user
    trial = request.query_params.get('is_trial', None)
    paid = request.query_params.get('is_paid', None)
    if user:
        if trial:
            user.is_trial_on = True
            trial_period = TrialPeriodDays.objects.get(id=1)
            days = trial_period.days
            user.trial_expiry_date_time = user.date_joined + datetime.timedelta(days=days)
        if paid:
            user.is_paid_user = True
        user.save()

        return Response({'message': 'Updated Successfully'})
    else:
        return Response({'error': 'Not a valid User'})

@api_view(['GET'])
def upgrade_now(request):
    user = request.user
    user_forms = CustomerForms.objects.filter(user_id=user.id)
    if user_forms:
        user_forms.update(status='D')
    if user.role_type == 'OA':
        user_email = user.email
        users_of_user = CustomUser.objects.filter(email__contains=user_email.split('@')[1], role_type='OE')
        if users_of_user:
            users_of_user.update(is_active=False)
    signup_fee_ob = DeclaredPaymentFee.objects.get(id=1)
    payment_amount = float(signup_fee_ob.signup_fee)
    return_url = str('http://' + get_current_site(request).domain + reverse('exec_payment'))
    print "this is return url"
    print return_url
    payment = Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": return_url,
            "cancel_url": "http://192.168.0.113:8000/admin"
        },
        "transactions": [
            {
                "amount": {
                    "total": payment_amount,
                    "currency": "INR",
                    "details": {
                        "subtotal": payment_amount,
                        "tax": "0.00",
                        "shipping": "0.00",
                        "handling_fee": "0.00",
                        "shipping_discount": "0.00",
                        "insurance": "0.00"
                    }
                },
                "description": "This is the payment for upgrading the account of a user",
                # "custom": "EBAY_EMS_90048630024435",
                # "invoice_number": "4878758967312",
                "payment_options": {
                    "allowed_payment_method": "INSTANT_FUNDING_SOURCE"
                },
                "soft_descriptor": "ECHI5786786",
                "item_list": {
                    "items": [
                        {
                            "name": "hat",
                            "description": "Brown color hat",
                            "quantity": "5",
                            "price": "0.00",
                            "tax": "0.00",
                            "sku": "1",
                            "currency": "INR"
                        },
                        {
                            "name": "handbag",
                            "description": "Black color hand bag",
                            "quantity": "1",
                            "price": "0.00",
                            "tax": "0.00",
                            "sku": "product34",
                            "currency": "INR"
                        }
                    ],
                    "shipping_address": {
                        "recipient_name": user.username,
                        "line1": "Eforms",
                        "line2": "Application",
                        "city": "Kanpur",
                        "country_code": "IN",
                        "postal_code": "208001",
                        "phone": "011862212345678",
                        "state": "CA"
                    }
                }
            }
        ],
        "note_to_payer": "Contact us for any questions on your order.",
    })
    settings.PAYMENT_OB = payment
    if payment.create():
        # Extract redirect url
        for link in payment.links:
            print link
            if link.method == "REDIRECT":
                # Capture redirect url
                redirect_url = str(link.href)
                return redirect(redirect_url)
    else:
        return Response({'error': payment.error})

@api_view(['GET'])
def configuration_api(request):

    fee_start = DeclaredPaymentFee.objects.get(id=1)
    if fee_start:
        serializer = DeclaredPaymentFeeSerializer(fee_start)
        data = serializer.data
        trial = TrialPeriodDays.objects.filter()
        if trial:
            trial = trial[0]
            trial_dict = {}
            trial_dict['trial_period'] = trial.days
        data.update(trial_dict)

        return Response(data)


def apple_app_site_association(request):
    from django.http import JsonResponse
    with open(settings.BASE_DIR + '/assets/apple-app-site-association.json', 'r') as file_ob:
        file_content = json.load(file_ob)
    print file_content
    print type(file_content)
    if file_content:
        return JsonResponse(file_content, content_type='application/pkcs7-mime', safe=False)
