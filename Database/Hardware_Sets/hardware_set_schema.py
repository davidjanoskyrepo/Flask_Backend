from marshmallow import Schema, fields

class HardwareSetSchema(Schema):
    hardware_set_name = fields.Str()
    # Availability is in form "cluster_name" = units_available
    # Will subtract units from this field, with error checks of course
    capacity = fields.Dict(keys=fields.Str(), values=fields.Int())
    availability = fields.Dict(keys=fields.Str(), values=fields.Int())
    description = fields.Str()
    # As of now all clusters have the same unit price
    price_per_unit = fields.Float()

class CheckOutHardwareSetSchema(Schema):
    user_name = fields.Str()
    hardware_set_name = fields.Str()
    # Availability is in form "cluster_name" = units_available
    cluster_name = fields.Str()
    unit_amount = fields.Int()
    # As of now all clusters have the same unit price
    price_per_unit = fields.Float()
    # Store the date time so we know which units to free in case of an update with less units
    # Also could be used for autobilling
    ticket_creation_timestamp = fields.Float()