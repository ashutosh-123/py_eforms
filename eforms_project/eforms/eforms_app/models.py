from __future__ import unicode_literals

from django.db import models
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import AbstractUser
import datetime
from rest_framework.response import Response

USER_ROLE_CHOICES = (
    ('A', 'Admin'),
    ('S', 'SuperUser'),
    ('OA', 'Organization Admin'),
    ('OE', 'Organization Employee'),
    ('C', 'Customer'),
)

CUSTOMER_FORM_STATUS = (
    ('D', 'Draft'),
    ('P', 'Published'),
    ('UP', 'Unpublished'),
    ('S', 'Submitted')
)

CUSTOMER_ORDER_STATUS = (
    ('P', 'PENDING'),
    ('C', 'CANCELLED'),
    ('CMP', 'COMPLETED')
)

CUSTOMER_PAYMENT_STATUS = (
    ('I', 'INITIATED'),
    ('P', 'PROCESSING'),
    ('C', 'COMPLETED'),
)

class Organisation(models.Model):

    organistation_name = models.CharField(db_index=True, max_length=254, null=True, blank=True)
    organisation_type = models.CharField(db_index=True, max_length=254, null=True, blank=True)
    organisation_location = models.CharField(max_length=254, null=True, blank=True)
    no_of_employees = models.IntegerField(null=True, blank=True)
    organisation_email = models.EmailField(db_index=True, null=True, max_length=254,unique=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.organistation_name)



class TrialPeriodDays(models.Model):

    days = models.IntegerField(null=True, blank=True)
    trial_period = models.CharField(max_length=20, null=True, blank=True)

class CustomUser(AbstractUser):

    email = models.EmailField(max_length=50, null=True, unique=True)
    address = models.CharField(max_length=254, null=True, blank=True)
    organisation = models.ForeignKey(Organisation, null=True, blank=True, db_index=True)
    role_type = models.CharField(max_length=5, choices=USER_ROLE_CHOICES, blank=True, db_index=True, default='C')
    profile_img = models.ImageField(null=True, blank=True)
    profile_url = models.CharField(max_length=254, null=True, blank=True)
    passcode = models.CharField(max_length=100, null=True, blank=True)
    dropbox_token = models.CharField(max_length=300,null=True, blank=True)
    google_drive_token = models.CharField(max_length=300, null=True, blank=True)
    is_trial_on = models.BooleanField(default=True, blank=True)
    is_paid_user = models.BooleanField(default=False, blank=True)
    trial_expiry_date_time = models.DateTimeField(default=datetime.datetime.now() + datetime.timedelta(
        days=TrialPeriodDays.objects.filter()[0].days), null=True, blank=True)
    remaining_trial_time = models.BigIntegerField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)

    def __unicode__(self):
        return str(self.username)

class SignUpPromoCode(models.Model):

    promocode = models.CharField(max_length=20, null=True, blank=True)
    discount = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    #user = models.ForeignKey(CustomUser, null=True, blank=True)
    is_enabled = models.BooleanField(default=False, blank=True)

    def __unicode__(self):
        return str(self.promocode)

    def save(self, *args, **kwargs):
        if (self.expiry_date > datetime.datetime.now()):
            super(SignUpPromoCode, self).save(*args, **kwargs)
        else:
            return Response({'message': 'Invalid date'})

class CustomerForms(models.Model):

    title = models.CharField(max_length=254, null=True, blank=True, db_index=True)
    form_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    description = models.CharField(max_length=254, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    user = models.ForeignKey(CustomUser, null=True, db_index=True, on_delete=models.CASCADE)
    publish_id = models.IntegerField(null=True, blank=True)
    created_by = models.CharField(max_length=200, null=True, blank=True)
    status = models.CharField(max_length=5, choices=CUSTOMER_FORM_STATUS, null=True, blank=True, db_index=True,
                              default='D')
    is_deleted = models.BooleanField(default=False, blank=True)
    min = models.IntegerField(null=True, blank=True)
    max = models.IntegerField(null=True, blank=True)

    def __unicode__(self):
        return str(self.title)


class CustomerFormsPromoCode(models.Model):

    promocode = models.CharField(max_length=20, null=True, blank=True)
    #user = models.ForeignKey(CustomUser, null=True, blank=True)
    discount = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    is_enabled = models.BooleanField(default=False, blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True)

    def __unicode__(self):
        return str(self.promocode)

    def save(self, *args, **kwargs):
        if (self.expiry_date > datetime.datetime.now()):
            super(CustomerFormsPromoCode, self).save(*args, **kwargs)
        else:
           # raise Exception('Expiry Date can not be less than today')
           return Response({'message': 'Invalid date'})


class AddUserPromoCode(models.Model):

    promocode = models.CharField(max_length=20, null=True, blank=True)
    #user = models.ForeignKey(CustomUser, null=True, blank=True)
    discount = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    is_enabled = models.BooleanField(default=False, blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True)

    def __unicode__(self):
        return str(self.promocode)

    def save(self, *args, **kwargs):
        if (self.expiry_date > datetime.datetime.now()):
            super(AddUserPromoCode, self).save(*args, **kwargs)
        else:
            #raise Exception('Expiry Date can not be less than today')
            return Response({'message': 'Invalid date'})




class DeclaredPaymentFee(models.Model):

    signup_charge = models.DecimalField(decimal_places=2, max_digits=10, null=True, blank=True)
    add_organisation_user_charge = models.DecimalField(decimal_places=2, max_digits=10, null=True, blank=True)
    published_form_charge = models.DecimalField(decimal_places=2, max_digits=10, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class AdminFormModules(models.Model):

    title = models.CharField(max_length=254, null=True, blank=True, db_index=True)
    customers = models.ManyToManyField(CustomerForms, blank=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, blank=True, db_index=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)

    description = models.CharField(max_length=254, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    user = models.ForeignKey(CustomUser, null=True, db_index=True, on_delete=models.CASCADE)
    created_by = models.CharField(max_length=200, null=True, blank=True)
    min = models.IntegerField(null=True, blank=True)
    max = models.IntegerField(null=True, blank=True)
    is_default = models.BooleanField(default=False)

    def __unicode__(self):
        return str(self.title)


class CustomerTemplates(models.Model):

    title = models.CharField(max_length=254, null=True, blank=True, db_index=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    field_id = models.CharField(max_length=254, null=True, blank=True, db_index=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)

    description = models.CharField(max_length=254, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    user = models.ForeignKey(CustomUser, null=True, db_index=True, on_delete=models.CASCADE)
    created_by = models.CharField(max_length=200, null=True, blank=True)
    min = models.IntegerField(null=True, blank=True)
    max = models.IntegerField(null=True, blank=True)
    orderno = models.IntegerField(null=True, blank=True)
    is_default = models.BooleanField(default=False)

    def __unicode__(self):
        return str(self.title)

class WelcomeModuleAdmin(models.Model):

    video_activated = models.BooleanField(default=False, blank=True)
    logo_activated = models.BooleanField(default=False, blank=True)
    logo = models.ImageField(null=True, blank=True)
    video = models.FileField(upload_to='video/admin_videos/', null=True, blank=True)
    image_activated = models.BooleanField(default=False, blank=True)
    image = models.ImageField(null=True, blank=True)
    message_activated = models.BooleanField(default=False, blank=True)
    message = models.CharField(max_length=10000, null=True,  blank=True)
    # is_google_drive = models.BooleanField(blank=True, default=False)
    # is_dropbox = models.BooleanField(blank=True, default=False)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)

    is_enabled = models.BooleanField(default=True, blank=True)
    def __unicode__(self):
        return str(self.message)

class WelcomeModuleCustomer(models.Model):


    message = models.CharField(null=True, max_length=10000, blank=True)
    video = models.CharField(max_length=500, null=True, blank=True)
    image = models.ImageField(null=True, blank=True)
    logo = models.ImageField(null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, on_delete=models.CASCADE)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    orderno = models.IntegerField(null=True, blank=True)

    def __unicode__(self):
        return str(self.message)

class SubmitModuleAdmin(models.Model):

    message = models.CharField(max_length=10000, null=True, blank=True)
    is_enabled = models.BooleanField(default=True, blank=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.message)


class SubmitModuleCustomer(models.Model):

    message = models.CharField(max_length=10000, null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    orderno = models.IntegerField(null=True, blank=True)

    def __unicode__(self):
        return str(self.message)

class SubmitFormUser(models.Model):

    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    email = models.CharField(max_length=50, null=True, blank=True)

    def __unicode__(self):
        return str(self.first_name)


class Submittedforms(models.Model):

    status = models.CharField(max_length=5, choices=CUSTOMER_FORM_STATUS, null=True, blank=True, db_index=True)
    published_customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, blank=True)
    user_data = models.ForeignKey(SubmitFormUser, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    title = models.CharField(max_length=300, null=True, blank=True)
    device_token = models.CharField(max_length=300, null=True, blank=True)
    form_price = models.DecimalField(decimal_places=2, max_digits=10, null=True, blank=True)

class SingleCheckBox(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    group = models.BooleanField(default=False, blank=True)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    is_required = models.BooleanField(blank=True, default=False)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    step = models.IntegerField(null=True, blank=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)

class SingleCheckBoxData(models.Model):

    singlecheckbox = models.ForeignKey(SingleCheckBox, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class SingleRadioBox(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class SingleRadioBoxData(models.Model):

    listradiobox = models.ForeignKey(SingleRadioBox, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class TextField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    placeholder = models.CharField(max_length=254, null=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    max_length = models.IntegerField(null=True)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class TextFieldData(models.Model):

    textfield = models.ForeignKey(TextField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class NumberInput(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    placeholder = models.CharField(max_length=254, null=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    max_length = models.IntegerField(null=True)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class NumberInputData(models.Model):

    numberinput = models.ForeignKey(NumberInput, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class TextArea(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    placeholder = models.CharField(max_length=254, null=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    max_length = models.IntegerField(null=True)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)

class TextAreaData(models.Model):

    textarea = models.ForeignKey(TextArea, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class RatingField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class RatingFieldData(models.Model):

    rating = models.ForeignKey(RatingField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class ImageField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    center = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    src = models.CharField(max_length=254, null=True, db_index=True, blank=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class ImageFieldData(models.Model):

    image = models.ForeignKey(ImageField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class ImageOverlay(models.Model):

    field_id = models.CharField(max_length=254, null=True, blank=True)
    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class ImageOverlayData(models.Model):

    imageoverlay = models.ForeignKey(ImageOverlay, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class DateTimeField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    placeholder = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    defaulttoday = models.BooleanField(blank=True, default=False)
    readonly = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)

class DateTimeFieldData(models.Model):

    datefield = models.ForeignKey(DateTimeField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class DropDown(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class DropDownData(models.Model):

    dropdown = models.ForeignKey(DropDown, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class Tags(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    canHaveAnswer = models.BooleanField(blank=True, default=False)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class TagsData(models.Model):

    tag = models.ForeignKey(Tags, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class HeaderField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    bold = models.BooleanField(blank=True, default=False)
    italic = models.BooleanField(blank=True, default=False)
    static = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    placeholder = models.CharField(max_length=254, null=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class HeaderFieldData(models.Model):

    header = models.ForeignKey(HeaderField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class ParagraphField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    bold = models.BooleanField(blank=True, default=False)
    italic = models.BooleanField(blank=True, default=False)
    static = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    placeholder = models.CharField(max_length=254, null=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class ParagraphFieldData(models.Model):

    paragraphfield = models.ForeignKey(ParagraphField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class SignatureField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    placeholder = models.CharField(max_length=254, null=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class SignatureFieldData(models.Model):

    signaturefield = models.ForeignKey(SignatureField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class LabelField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    bold = models.BooleanField(blank=True, default=False)
    italic = models.BooleanField(blank=True, default=False)
    static = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    placeholder = models.CharField(max_length=254, null=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class LabelFieldData(models.Model):

    labelfield = models.ForeignKey(LabelField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class LineBreakField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    bold = models.BooleanField(blank=True, default=False)
    italic = models.BooleanField(blank=True, default=False)
    static = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class RangeField(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True, blank=True)
    min_label = models.CharField(max_length=254, null=True, blank=True)
    max_label = models.CharField(max_length=254, null=True, blank=True)
    step = models.IntegerField(blank=True, null=True)
    default_value = models.IntegerField(blank=True, null=True)
    min_value = models.IntegerField(blank=True, null=True)
    max_value = models.IntegerField(blank=True, null=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    step = models.IntegerField(null=True, blank=True)
    stepno = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class RangeFieldData(models.Model):

    rangefield = models.ForeignKey(RangeField, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)


class Camera(models.Model):

    label = models.CharField(max_length=254, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, db_index=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    group = models.BooleanField(default=False, blank=True)
    is_required = models.BooleanField(blank=True, default=False)
    help_text = models.CharField(max_length=254, null=True, blank=True)
    name = models.CharField(max_length=254, null=True, db_index=True)
    field_id = models.CharField(max_length=254, null=True, db_index=True)
    step = models.IntegerField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    submitform = models.ManyToManyField(Submittedforms, blank=True)

    def __unicode__(self):
        return str(self.label)


class CameraData(models.Model):

    camera = models.ForeignKey(Camera, null=True, db_index=True)
    input_data = models.CharField(max_length=254, null=True)
    input_data_text = models.CharField(max_length=254, null=True)
    submitform = models.ForeignKey(Submittedforms, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)



class Options(models.Model):

    option_value = models.CharField(max_length=254, null=True)
    option_label = models.CharField(max_length=254, null=True)
    option_field_id = models.CharField(max_length=254, null=True)
    option_text = models.CharField(max_length=254, null=True)
    selected = models.BooleanField(default=False)
    singlecheckbox = models.ForeignKey(SingleCheckBox, null=True, db_index=True)
    singleradiobox = models.ForeignKey(SingleRadioBox, null=True, db_index=True)
    dropdown = models.ForeignKey(DropDown, null=True, db_index=True)
    tags = models.ForeignKey(Tags, null=True, db_index=True)

    def __unicode__(self):
        return str(self.id)

class ForgetPasswordToken(models.Model):

    token = models.CharField(max_length=254)
    user = models.ForeignKey(CustomUser, null=True, related_name='user', db_index=True, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.id)

class EmailVerificationToken(models.Model):

    token = models.CharField(max_length=254)
    user = models.ForeignKey(CustomUser, null=True, related_name='user_email_verify', db_index=True, on_delete=models.CASCADE)
    expiration_time = models.DateTimeField(null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.id)

class PrivacyPolicy(models.Model):

    content = models.TextField(max_length=1000, null=True)

    def __unicode__(self):
        return str(self.id)

class TermsAndConditions(models.Model):

    content = models.TextField(max_length=1000, null=True)

    def __unicode__(self):
        return str(self.id)

class Disclaimer(models.Model):

    content = models.TextField(max_length=1000, null=True)

    def __unicode__(self):
        return str(self.id)

class Cart(models.Model):

    user = models.ForeignKey(CustomUser, null=True, blank=True, db_index=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True, db_index=True)
    form_amount = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    discount = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now_add=True)


    def __unicode__(self):
        return str(self.id)

class PaymentGateway(models.Model):

    pg_name = models.CharField(max_length=200, null=True, blank=True)
    pg_id = models.CharField(max_length=200, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class FormLinkToken(models.Model):

    token = models.CharField(max_length=254)
    user = models.ForeignKey(CustomUser, null=True, blank=True)
    form_id = models.IntegerField(null=True, blank=True)
    key_expires = models.DateTimeField(null=True)

    def __unicode__(self):
        return str(self.id)

class Payment(models.Model):

    pg = models.ForeignKey(PaymentGateway, null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    payment_status = models.CharField(max_length=2, choices=CUSTOMER_PAYMENT_STATUS, null=True, blank=True)
    payment_mode = models.CharField(max_length=50, null=True, blank=True)
    payment_id = models.CharField(max_length=50, null=True, blank=True)
    payer_id = models.CharField(max_length=50, null=True, blank=True)
    payment_at = models.DateTimeField(auto_now_add=True)
    payable_amount = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class Conditions(models.Model):

    if_field = models.CharField(max_length=200, null=True, blank=True)
    state = models.CharField(max_length=200, null=True, blank=True)
    condition = models.CharField(max_length=200, null=True, blank=True)
    field = models.CharField(max_length=200, null=True, blank=True)
    value = models.CharField(max_length=200, null=True, blank=True)
    form = models.ForeignKey(AdminFormModules, null=True, blank=True)
    customer_template = models.ForeignKey(CustomerTemplates, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.id)

class UnlockModuleAdmin(models.Model):

    message = models.CharField(max_length=10000, null=True, blank=True)
    is_enabled = models.BooleanField(default=True, blank=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.id)

class UnlockModuleCustomer(models.Model):

    message = models.CharField(max_length=10000, null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    orderno = models.IntegerField(null=True, blank=True)



class DropboxModuleAdmin(models.Model):

    is_enabled = models.BooleanField(default=True, blank=True)
    module_price =  models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

class DropboxModuleCustomer(models.Model):

    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    module_price =  models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    orderno = models.IntegerField(null=True, blank=True)
    def __unicode__(self):
        return str(self.id)

class GoogleDriveModuleCustomer(models.Model):

    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    orderno = models.IntegerField(null=True, blank=True)
    def __unicode__(self):
        return str(self.id)


class GoogleDriveModuleAdmin(models.Model):

    is_enabled = models.BooleanField(default=True, blank=True)
    module_price =  models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.id)

class EmailModuleCustomer(models.Model):

    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    module_price =  models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    user = models.ForeignKey(CustomUser, null=True, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    email = models.CharField(max_length=300, null=True, blank=True)
    orderno = models.IntegerField(null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class EmailModuleAdmin(models.Model):

    is_enabled = models.BooleanField(default=True, blank=True)
    module_price = models.DecimalField(decimal_places=2, max_digits=10 , null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)
    email = models.CharField(max_length=300, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class ImageUploadModel(models.Model):

    form = models.ForeignKey(CustomerForms, null=True, blank=True)
    element = models.CharField(max_length=200, null=True, blank=True)
    field_id = models.CharField(max_length=300, null=True, blank=True)
    image = models.ImageField(null=True, blank=True)
    video = models.FileField(upload_to='video/', null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

class PublishFormHandling(models.Model):

    publish_form_id = models.IntegerField(null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    form_price = models.DecimalField(decimal_places=2, max_digits=10, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    modified_on = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return str(self.id)

class SubmittedFormPdf(models.Model):

    pdf = models.FileField(upload_to='pdfs/', null=True, blank=True)
    customer_form = models.ForeignKey(CustomerForms, null=True, blank=True)
    submitted_form = models.ForeignKey(Submittedforms, null=True, blank=True)

    def __unicode__(self):
        return str(self.id)

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)





