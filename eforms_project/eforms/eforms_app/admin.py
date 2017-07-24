# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from models import *
from django.contrib.auth.admin import UserAdmin

admin.site.disable_action('delete_selected')
admin.site.empty_value_display = "N/A"

admin.site.site_header = 'Formlio'
admin.site.site_title = 'Formlio'
admin.site.index_title = 'Formlio'



class TrialPeriodDaysAdmin(admin.ModelAdmin):

    list_display = ['trial_period', 'days']

    def change_view(self, request, object_id, extra_context=None):
        extra_context = extra_context or {}
        extra_context['show_delete'] = False
        return super(TrialPeriodDaysAdmin, self).change_view(request, object_id, extra_context=extra_context)

class CustomerFormsPromoCodeAdmin(admin.ModelAdmin):

    list_display = ['promocode', 'discount', 'is_enabled', 'expiry_date', 'customer_form']
    list_filter = ('promocode', 'is_enabled', 'customer_form')
    ordering = ('expiry_date',)
    search_fields = ('promocode',)
    # def get_actions(self, request):
    #     print "these are all actions"
    #     actions = super(CustomerFormsPromoCodeAdmin, self).get_actions(request)
    #     del actions['delete_selected']
    #     return actions


    def change_view(self, request, object_id, extra_context=None):

        extra_context = extra_context or {}
        extra_context['show_delete'] = False
        return super(CustomerFormsPromoCodeAdmin, self).change_view(request, object_id, extra_context=extra_context)

class AddUserPromoCodeAdmin(admin.ModelAdmin):

    list_display = ['promocode', 'discount', 'is_enabled', 'expiry_date']
    list_filter = ('promocode', 'is_enabled',)
    ordering = ('expiry_date',)
    search_fields = ('promocode',)

    # def get_actions(self, request):
    #     actions = super(AddUserPromoCodeAdmin, self).get_actions(request)
    #     del actions['delete_selected']
    #     return actions

    def change_view(self, request, object_id, extra_context=None):
        extra_context = extra_context or {}
        extra_context['show_delete'] = False
        return super(AddUserPromoCodeAdmin, self).change_view(request, object_id, extra_context=extra_context)

class SignUpPromoCodeAdmin(admin.ModelAdmin):

    list_display = ['promocode', 'discount', 'is_enabled', 'expiry_date']
    list_filter = ('promocode', 'is_enabled',)
    ordering = ('expiry_date',)
    search_fields = ('promocode',)

    # def get_actions(self, request):
    #     actions = super(SignUpPromoCodeAdmin, self).get_actions(request)
    #     del actions['delete_selected']
    #     return actions


    def change_view(self, request, object_id, extra_context=None):
        extra_context = extra_context or {}
        extra_context['show_delete'] = False
        return super(SignUpPromoCodeAdmin, self).change_view(request, object_id, extra_context=extra_context)

class DeclaredPaymentFeeAdmin(admin.ModelAdmin):

    list_display = ['signup_charge', 'add_organisation_user_charge', 'published_form_charge']

    # def get_actions(self, request):
    #     actions = super(DeclaredPaymentFeeAdmin, self).get_actions(request)
    #     del actions['delete_selected']
    #     return actions

    def change_view(self, request, object_id, extra_context=None):
        extra_context = extra_context or {}
        extra_context['show_delete'] = False
        return super(DeclaredPaymentFeeAdmin, self).change_view(request, object_id, extra_context=extra_context)

admin.site.register(CustomUser)
admin.site.register(CustomerFormsPromoCode, CustomerFormsPromoCodeAdmin)
admin.site.register(AddUserPromoCode, AddUserPromoCodeAdmin)
admin.site.register(SignUpPromoCode, SignUpPromoCodeAdmin)
admin.site.register(TrialPeriodDays, TrialPeriodDaysAdmin)
admin.site.register(DeclaredPaymentFee, DeclaredPaymentFeeAdmin)
admin.site.register(AdminFormModules)
admin.site.register(Organisation)
admin.site.register(SingleCheckBox)
admin.site.register(SingleCheckBoxData)
admin.site.register(SingleRadioBox)
admin.site.register(SingleRadioBoxData)
admin.site.register(TextField)
admin.site.register(TextFieldData)
admin.site.register(DateTimeField)
admin.site.register(DateTimeFieldData)
admin.site.register(DropDown)
admin.site.register(DropDownData)
admin.site.register(HeaderField)
admin.site.register(ParagraphField)
admin.site.register(SignatureField)
admin.site.register(Options)
admin.site.register(ForgetPasswordToken)
admin.site.register(EmailVerificationToken)
admin.site.register(PrivacyPolicy)
admin.site.register(TermsAndConditions)
admin.site.register(Disclaimer)
admin.site.register(CustomerForms)
admin.site.register(WelcomeModuleAdmin)
admin.site.register(WelcomeModuleCustomer)
admin.site.register(Submittedforms)
admin.site.register(Conditions)


