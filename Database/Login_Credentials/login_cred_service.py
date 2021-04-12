import hashlib
import base64
import bcrypt
from cryptography.fernet import Fernet
import os.path
from bson.objectid import ObjectId

from ..db_entry import DataSet
from ..mongo import MongoEntry
from .login_cred_schema import LoginSetSchema

class LoginSetService():
    """
    Sets the client which is an abstract 'LoginSet' on the frontend
    and a mongodb entry on the backend.
    """

    SALT_ROUNDS = 16
    LOGIN_COLLECTION_NAME = "LoginSet"

    def __init__(self):
        self.key = ""
        self.login_set_client = DataSet(adapter=MongoEntry(self.LOGIN_COLLECTION_NAME))

    """
    Generates a key and save it into a file
    If you delete the file its gg for all that data mapped to that key
    """
    def generate_key(self):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        self.key = key
        return key

    """
    Load the previously generated key or make a new one if first call
    """
    def load_key(self):
        try:
            if self.key == "":
                key_file = open("secret.key", "rb")
                # exists
                self.key = key_file.read()
                key_file.close()
                return self.key
            else:
                return self.key
        except FileNotFoundError:
            # doesn't exist
            print("CREATING NEW KEY!!!")
            return self.generate_key()

    """
    Encrypts a message
    """
    def encrypt_message(self, message):
        key = self.load_key()
        encoded_message = message.encode()
        f = Fernet(key)
        encrypted_message = f.encrypt(encoded_message)

        #print(encrypted_message)
        return encrypted_message

    """
    Decrypts an encrypted message
    """
    def decrypt_message(self, encrypted_message):
        key = self.load_key()
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        decoded_message = decrypted_message.decode()

        #print(decrypted_message.decode())
        return decoded_message

    """
    Hash a user_password for the first time
    Using bcrypt, the salt is saved into the hash itself preventing rainbow table attacks
    We use sha256 and encode using base 64 to bypass the max length problems of blowfish
    """
    def get_hashed_user_password(self, plain_text_user_password):
      return bcrypt.hashpw(base64.b64encode(hashlib.sha256(str(plain_text_user_password).encode()).digest()), bcrypt.gensalt(rounds = self.SALT_ROUNDS))

    """
    Check hashed user_password. Using bcrypt, the salt is saved into the hash itself
    """
    def check_user_password(self, plain_text_user_password, hashed_user_password):
      return bcrypt.checkpw(base64.b64encode(hashlib.sha256(str(plain_text_user_password).encode()).digest()), hashed_user_password)

    """
    Method that returns the count of login sets
    """
    def count_login_set(self):
        login_sets = list(self.login_set_client.find_all({})) or []
        if login_sets != []:
            #print(login_sets)
            return int(len(login_sets))
        else:
            return 0

    """
    Finds a specific login_set by user_name (client side encrypted before send off)
    Could use find_one but want the database to be ensured to be unique users
    """
    def find_login_set(self, user_name):
        # Get users
        #print(self.login_set_client.find_all({}))
        login_sets = list(self.login_set_client.find_all({})) or []
        #print(login_sets, type(login_sets))
        if login_sets != []:
            #print("theres an entry")
            #print(login_set.get('user_name'), type(login_set.get('user_name')))
            for login_set in login_sets:
                #print("In login set, encrypted user {}".format(login_set.get('user_name')))
                #print("In find login, decrypted user {}".format(self.decrypt_message(login_set.get('user_name'))))
                if (self.decrypt_message(login_set.get('user_name')) == user_name):
                    return True
        return False

    """
    Creates a specific login_set with an encrypted user_name and hashed user_password if new user
    """
    def create_login_set_for(self, user_name, user_password, user_email):
        #print("create")
        if self.find_login_set(user_name) == False:
            # Encrypt
            user_name = self.encrypt_message(str(user_name))
            # Hash
            user_password = self.get_hashed_user_password(str(user_password))
            # Encrypt
            user_email = self.encrypt_message(str(user_email))
            #print("making new user")
            login_set = self.login_set_client.create(self.prepare_login_set(user_name, user_password, user_email))
            #print(login_set)
            #print(True if login_set != None else False)
            return True if login_set != None else False
        else:
            #print("user already exists")
            return False
    
    """
    Updates a specific login_set by user_name with new user_password, returns records affected which should be 1
    """
    def update_login_set_with(self, user_name, user_password, user_email):
        records_affected = 0
        # Get users
        login_sets = list(self.login_set_client.find_all({})) or []
        #print(login_set, type(login_set))
        if login_sets != []:
            for login_set in login_sets:
                if (self.decrypt_message(login_set.get('user_name')) == user_name):
                    # Encrypt
                    user_name = self.encrypt_message(str(user_name))
                    # Hash
                    user_password = self.get_hashed_user_password(str(user_password))
                    # Encrypt
                    user_email = self.encrypt_message(str(user_email))
                    records_affected = self.login_set_client.update({'user_name': login_set.get('user_name')}, self.prepare_login_set(user_name, user_password, user_email))
        return True if records_affected > 0 else False

    """
    Deletes a specific login_set by user_name
    """
    def delete_login_set_for(self, user_name):
        records_affected = 0
        # Get users
        login_sets = list(self.login_set_client.find_all({})) or []
        #print(login_set, type(login_set))
        if login_sets != []:
            for login_set in login_sets:
                if (self.decrypt_message(login_set.get('user_name')) == user_name):
                    #print("Deleting : {}".format(login_set))
                    records_affected = self.login_set_client.delete({'user_name': login_set.get('user_name')})
                    #print(records_affected)
        return True if records_affected > 0 else False

    """
    Dumps login_set by user
    """
    def dump(self, user_name):
        login_set_dump = None
        login_sets = list(self.login_set_client.find_all({})) or []
        #print(login_set, type(login_set))
        if login_sets != []:
            for login_set in login_sets:
                if (self.decrypt_message(login_set.get('user_name')) == user_name):
                    login_set_dump = LoginSetSchema.dump(login_set)
        return login_set_dump

    """
    Returns the _id for a given user_name
    """
    def get_id(self, user_name):
        # Get users
        login_sets = list(self.login_set_client.find_all({})) or []
        if login_sets != []:
            for login_set in login_sets:
                if (self.decrypt_message(login_set.get('user_name')) == user_name):
                    return login_set.get('_id')
        return None

    """
    Get user by _id
    """
    def get_user_by_id(self, id):
        user = self.login_set_client.find({'_id' : ObjectId(id)}) or None
        return user

    """
    Get user_name by _id
    """
    def get_user_name_by_id(self, id):
        user = self.login_set_client.find({'_id' : ObjectId(id)}) or None
        #print("USER in get_user_name_by_id")
        #print(user)
        if user:
            user_name = self.decrypt_message(user.get('user_name'))
            return user_name
        return "Anonymous"

    """
    Get user_active by _id
    """
    def get_user_active_by_id(self, id):
        user = self.login_set_client.find({'_id' : ObjectId(id)}) or None
        if user:
            user_active = user.get('user_active')
            return user_active
        return False

    """
    Used to update/create a login_set
    """
    def prepare_login_set(self, user_name, user_password, user_email):
        login_set = {}
        login_set['user_name'] = user_name
        login_set['user_password'] = user_password
        login_set['user_active'] = True
        login_set['user_email'] = user_email
        schema = LoginSetSchema()
        result = schema.load(login_set)
        return result

    """
    Return True if login creds match else False
    """
    def validate_login_set(self, plain_text_user_name, plain_text_user_password):
        # Get users
        login_sets = list(self.login_set_client.find_all({})) or []
        #print(login_sets, type(login_sets))
        if login_sets != []:
            #print(login_set)
            for login_set in login_sets:
                if (self.decrypt_message(login_set.get('user_name')) == plain_text_user_name):
                    return True if self.check_user_password(plain_text_user_password, login_set.get('user_password')) else False
