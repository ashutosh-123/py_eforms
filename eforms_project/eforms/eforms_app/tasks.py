from eforms import celery_app
import dropbox, requests
from time import sleep
import reportlab, os
import json
from .models import *
from django.core.mail import EmailMessage
import datetime
from json2html import *
from collections import OrderedDict
from operator import itemgetter
import pdfkit
@celery_app.task()
def create_pdf(form_data, submit_form_id, message="Its Ashutosh"):
    customer_form_id = form_data.get('customer_form_id', None)
    customer_form = CustomerForms.objects.get(id=customer_form_id)
    organisation_user_id = customer_form.user.id
    organisation = CustomUser.objects.get(id=organisation_user_id)
    customer_form_data = form_data.get('form', None)
    filepath = "/home/startxlabs/StartxLabs/eforms_project/eforms/media/NEWSubmittedForm_{0}.pdf".format(
        datetime.datetime.now().strftime("%H%M%S"))
    if form_data:
        html = ""
        for template in customer_form_data:
            template_data = template.get('template', None)

            if template_data:
                sorted_template_data = sorted(template_data, key=itemgetter('step'))
                template_data = sorted_template_data
                for component in template_data:
                    for key, value in component.items():
                        input_data = ""
                        content = ""
                        if key == 'label':
                            label = value
                        if key == 'input_data':
                            input_data = value
                        if key == 'content':
                            content = value
                        if input_data:
                            html = html + "<h2 style='font-size:16px;'>" + label + "</h2>" + "<p>" + input_data + "</p>"
                        if content:
                            html = html + "<h1 style='font-size:18px;'>" + content + "</h1>"
    pdf = pdfkit.from_string(html, filepath)
    print pdf
    submit_form = Submittedforms.objects.get(id=submit_form_id)
    SubmittedFormPdf.objects.create(pdf=filepath,
                                    customer_form=customer_form,
                                    submitted_form=submit_form)
    body = 'Hi, this is the form submitted by {}'.format(submit_form.user_data.first_name + " " +
                                                         submit_form.user_data.last_name)
    # if EmailModuleCustomer.objects.filter(customer_form=customer_form, user=organisation).exists():
    #     print "this is email module"
    #     users = EmailModuleCustomer.objects.filter(customer_form=customer_form, user=organisation)
    #     if users:
    #        user_ob = users[0]
    #        if user_ob.email:
    #            user_email = user_ob.email
    #     message = EmailMessage('Form has been Submitted', body,
    #                            '',
    #                            [user_email, ])
    #     # attachment = open(filepath, 'rb')
    #     # content = attachment.read()
    #     message.attach('Submit.pdf', pdf_file.read(), 'application/pdf')
    #     message.send(fail_silently=False)
    #
    # if DropboxModuleCustomer.objects.filter(customer_form=customer_form, user=organisation).exists():
    #     if organisation.dropbox_token:
    #         user_token = organisation.dropbox_token
    #         dbx = dropbox.Dropbox(user_token)
    #         #file_size = os.path.getsize(filepath)
    #
    #         dbx.files_upload(bytes(pdf_file.read()), '/Submit.pdf')
    #         pdf_file.close()
    #     else:
    #         raise Exception('Organisation is not connected to dropbox')
    #
    # if GoogleDriveModuleCustomer.objects.filter(customer_form=customer_form, user=organisation).exists():
    #
    #     if organisation.google_drive_token:
    #         access_token = organisation.google_drive_token
    #         file_size = os.path.getsize(filepath)
    #         headers = {
    #             'Authorization': 'Bearer' + ' ' + access_token,
    #             'Content-Length': str(file_size),
    #             'Content-Type': 'application/pdf'
    #         }
    #         data = pdf_file.read()
    #         pdf_file.close()
    #         pl = {"data": data, "title": "Test PDF"}
    #         file_upload_url = 'https://www.googleapis.com/upload/drive/v3/fi?uploadType=media'
    #         resp = requests.post(url=file_upload_url, data=pl, headers=headers)
    #         print resp.status_code

