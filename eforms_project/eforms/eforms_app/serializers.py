from rest_framework import serializers
from .models import *

class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = '__all__'
        depth = 2

class WelcomeModuleAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = WelcomeModuleAdmin
        fields = '__all__'

class SubmitModuleAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = SubmitModuleAdmin
        fields = '__all__'



class DropboxModuleAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = DropboxModuleAdmin
        fields = '__all__'



class EmailModuleAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = EmailModuleAdmin
        fields = '__all__'

class GoogleDriveModuleAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = GoogleDriveModuleAdmin
        fields = '__all__'


class WelcomeModuleCustomerSerializer(serializers.ModelSerializer):

    class Meta:
        model = WelcomeModuleCustomer
        fields = '__all__'

class SubmitModuleCustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubmitModuleAdmin
        fields = '__all__'

class UnlockModuleAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = UnlockModuleAdmin
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):

    API_KEY = serializers.SerializerMethodField('get_api_key')

    def get_api_key(self, obj):
        api_key = self.context.get('API-KEY', None)
        if api_key:
            return api_key
        return None

    class Meta:

        model = CustomUser
        fields = '__all__'
        depth = 2

class FormSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminFormModules
        fields = '__all__'

class CustomerFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerForms
        fields = '__all__'

class ChangePasswordSerializer(serializers.Serializer):

    old_password = serializers.CharField(required=True, allow_blank=True)
    new_password = serializers.CharField(required=True)

class TermsAndConditionsSerializer(serializers.ModelSerializer):

    class Meta:
        model = TermsAndConditions
        fields = '__all__'


class PrivacyPolicySerializer(serializers.ModelSerializer):

    class Meta:
        model = PrivacyPolicy
        fields = '__all__'


class DisclaimerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Disclaimer
        fields = '__all__'


class CartSerializer(serializers.ModelSerializer):
    class Meta:

        model = Cart
        fields = '__all__'

class SubmittedFormSerializer(serializers.ModelSerializer):
    class Meta:

        model = Submittedforms
        fields = '__all__'
        depth = 1

class ImageUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = ImageUploadModel
        fields = '__all__'
        depth = 1

class SubmittedFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = Submittedforms
        fields = '__all__'
        depth = 2

class CustomerFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerForms
        fields = '__all__'
        depth = 2

class DeclaredPaymentFeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeclaredPaymentFee
        fields = '__all__'

