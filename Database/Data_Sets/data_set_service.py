import json
from bson import ObjectId

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

from ..db_entry import DataSet
from ..mongo import MongoEntry
from .data_set_schema import DataSetSchema

class DataSetService(object):
    """
    Called on init, sets the client which is an abstract 'DataSet' on the frontend
    and a mongodb entry on the backend.
    """

    DATASET_COLLECTION_NAME = "DataSet"

    def __init__(self):
        self.data_set_client = DataSet(adapter=MongoEntry(self.DATASET_COLLECTION_NAME))

    """
    Method that returns the count of data sets
    """
    def count_data_set(self):
        data_sets = list(self.data_set_client.find_all({})) or []
        if data_sets != []:
            #print(data_sets)
            return int(len(data_sets))
        else:
            return 0

    """
    Grabs all the data_sets for user by name
    """
    def find_all_data_sets_for(self, user_name):
        data_sets = self.data_set_client.find_all({'user_name': user_name}) or []
        return json.encode(data_sets, cls=JSONEncoder)

    """
    Grabs all the not private data_sets
    """
    def find_all_public_data_sets(self):
        data_sets = self.data_set_client.find_all({'private': False}) or []
        return JSONEncoder().encode(data_sets)

    """
    Finds a specific data_set by name, ignores privacy
    """
    def find_data_set(self, data_set_name):
        data_set = self.data_set_client.find({'data_set_name': data_set_name})
        return JSONEncoder().encode(data_set)

    """
    Finds a specific data_set by name, check the user_name
    """
    def find_data_set_for(self, data_set_name, user_name):
        data_set = self.data_set_client.find({'data_set_name': data_set_name, 'user_name': user_name})
        return JSONEncoder().encode(data_set)


    """
    Creates a specific data_set
    Return true if sucessful create else false
    Ensures only unique data_set_name
    """
    def create_data_set_for(self, data_set_name, file_size, description, data_set_url, private, user_name):
        data_set = self.data_set_client.find({'data_set_name': data_set_name})
        if data_set == None:
            data_set = self.data_set_client.create(self.prepare_data_set(data_set_name, file_size, description, data_set_url, private, user_name))
            return True if data_set != None else False
        else:
            return False
    
    """
    Updates a specific data_set by name with new data
    If the name doesn't exist returns False as set not updated
    If it does update the set then returns true and changes reflected in db
    """
    def update_data_set_with(self, data_set_name, file_size, description, data_set_url, private, user_name):
        records_affected = 0
        data_set = self.data_set_client.find({'data_set_name': data_set_name, 'user_name': user_name})
        if data_set != None:
            records_affected = self.data_set_client.update({'data_set_name': data_set_name, 'user_name': user_name}, self.prepare_data_set(data_set_name, file_size, description, data_set_url, private, user_name))
        return True if records_affected > 0 else False

    """
    Deletes a specific data_set name if it exists
    """
    def delete_data_set_for(self, data_set_name, user_name):
        records_affected = self.data_set_client.delete({'data_set_name': data_set_name, 'user_name': user_name})
        return True if records_affected > 0 else False

    """
    Dumps all non-identifying info about the data_set
    """
    def dump(self, data_set):
        data_set_dump = None
        if data_set != None:
            schema = DataSetSchema(exclude=['_id'])
            data_set_dump = schema.dump(data_set)
            print(data_set_dump, type(data_set_dump))
        return data_set_dump

    """
    Used to update/create data_set
    """
    def prepare_data_set(self, data_set_name, file_size, description, data_set_url, private, user_name):
        data_set = {}
        data_set['data_set_name'] = data_set_name
        data_set['file_size'] = file_size
        data_set['description'] = description
        data_set['data_set_url'] = data_set_url
        data_set['private'] = private
        data_set['user_name'] = user_name
        schema = DataSetSchema()
        result = schema.load(data_set)
        return result
