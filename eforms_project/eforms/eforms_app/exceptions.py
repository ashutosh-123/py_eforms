from rest_framework.exceptions import APIException
from django.utils.encoding import force_text
from rest_framework import status
import json

class Exception(APIException):
    # status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    # default_detail = 'A server error occurred.'
    #
    # def __init__(self, detail=None, field=None, status_code=None):
    #     if status_code is not None: self.status_code = status_code
    #     if detail is not None:
    #         self.detail = json.dumps(detail)
    #     else:
    #         self.detail = json.dumps({'detail': force_text(self.default_detail)})

    pass