from marshmallow import Schema, fields

class DataSetSchema(Schema):
    data_set_name = fields.Str(required=True)
    file_size = fields.Str()
    description = fields.Str()
    data_set_url = fields.Str()
    private = fields.Boolean(required=True)
    user_name = fields.Str(required=True)
