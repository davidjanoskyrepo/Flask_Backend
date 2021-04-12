from marshmallow import Schema, fields

class BytesField(fields.Field):
    def _validate(self, value):
        if not isinstance(value, bytes):
            raise ValidationError('Invalid input type.')

        if value is None or value == b'':
            raise ValidationError('Invalid value')

class LoginSetSchema(Schema):
    user_name = BytesField(required=True)
    user_password = BytesField(required=True)
    user_active = fields.Boolean(required=True)
    user_email = BytesField(required=True)
