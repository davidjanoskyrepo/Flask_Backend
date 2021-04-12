"""
EE461L_Final_Project\Flask_Server\Tests\test_app.py

This file will create a simple local mock flask app and test the mongo db accessors
and mutator functionality.
"""

from flask import Flask, request, jsonify

# Bunch of imports required for session management
from flask_cors import CORS
from flask_login import (
    LoginManager,
    UserMixin,
    AnonymousUserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
    confirm_login,
)
from flask_wtf.csrf import CSRFProtect, generate_csrf

import unittest
import os

import json

# Setting the enviorn tag to mock uses a mock mongo db instead of the served db
os.environ["MOCK"] = "False"
os.environ["MONGO_DB_URI"] = "mongodb+srv://EE461L_Database_Username:EE461L_Database_Password@cluster0.mtond.mongodb.net/EE461L_Final_Project_DB?retryWrites=true&w=majority"

from Database.Login_Credentials.login_cred_service import LoginSetService
from Database.Data_Sets.data_set_service import DataSetService

# These two classes provide implementations of user classes
# https://flask-login.readthedocs.io/en/latest/#your-user-class
class User(UserMixin):
    def __init__(self, user_active):
        self.user_active = user_active

    def is_active(self):
        return self.user_active


class AnonUser(AnonymousUserMixin):
    user_name = "Anonymous"

def create_app() -> Flask:
    # Create exposed DB entry points
    my_login_set_service_g = LoginSetService()
    my_data_set_service_g = DataSetService()
    # Static folder can house things like images or any backend data not suited for db storage
    app = Flask(__name__, static_folder="Static")

    # Set configs
    # Set the server up for session based access
    app.config.update(
        DEBUG=True,
        # Sets the secret key for signing cookies and sessions
        SECRET_KEY="accidentally_leaked",
        # The HttpOnly flag set to True prevents any client-side usage of the session cookie
        SESSION_COOKIE_HTTPONLY=True,
        # limit the cookies to HTTPS traffic only for production.
        REMEMBER_COOKIE_HTTPONLY=True,
        # Set the timeout (in seconds) on cookies, default is 365 days, setting to 1 hr
        REMEMBER_COOKIE_DURATION=3600,
        # Lax loosens security a bit so that cookies will be sent cross-domain for the majority of requests.
        SESSION_COOKIE_SAMESITE="Lax",
        # disable csrf for tests, should form csrf tester
        WTF_CSRF_ENABLED = False,
    )

    # Setup the login manager
    login_manager = LoginManager()

    # If the identifiers for user (hash of ip and agent) do not match in strong mode for a non-permanent session, 
    # then the entire session (as well as the remember token if it exists) is deleted.
    login_manager.session_protection = "strong"
    # Set anon user, not really used yet
    login_manager.anonymous_user = AnonUser

    login_manager.init_app(app)

    """
    This callback is used to reload the user object from the user ID stored in the session. 
    It should take the unicode ID of a user, and return the corresponding user object.
    """
    @login_manager.user_loader
    def load_user(user_id):
        if user_id:
            this_user_active = my_login_set_service_g.get_user_active_by_id(user_id)
            user_model = User(user_active = this_user_active)
            user_model.id = user_id
            return user_model
        return None

    # Setup csrf, add csrf token to meta tag of front end
    # <meta name="csrf-token" content="{{ csrf_token() }}" />
    # Assign when component mounts
    # let csrf = document.getElementsByName("csrf-token")[0].content;
    # In app request need to form like this
    """
      fetch("/api/data", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrf,
        },
        credentials: "same-origin",
      })
    """
    # Since Flask is ultimately serving up the SPA, the CSRF cookie will be set automatically.
    # ***UNCOMMENT FOR REAL APP***
    #csrf = CSRFProtect(app)

    # Register the login routes

    # Default route
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def home(path):
        return jsonify({"error": "Error : use api routes!"})

    # Since front end seperate port and thread from backend we provide a sanity check function to ping the connection
    @app.route("/api/ping", methods=["GET"])
    def ping():
        return jsonify({"ping": "pong!"})

    # Get count of users
    @app.route("/api/login_set/count", methods=["GET"])
    def count_login_set():
        return jsonify({"login_count" : my_login_set_service_g.count_login_set()}), 200

    # Find one user by id
    @app.route("/api/login_set/find", methods=["POST"])
    def find_login_set():
        data = request.get_json()
        #print("route find")
        #print(request.url)
        # Get the request user_name arg
        this_user_name = data.get("user_name")
        #print(this_user_name)
        # Return the serialized (by marshmallow schema) user
        return jsonify({"login_found" : my_login_set_service_g.find_login_set(this_user_name)}), 200

    # Create one user by id with password
    @app.route("/api/login_set/create", methods=["POST"])
    def create_login_set():
        data = request.get_json()
        #print("route create")
        #print(request.url)
        # Get the request user_name arg
        this_user_name = data.get("user_name")
        #print(this_user_name)
        # Get the request user_password arg
        this_user_password = data.get("user_password")
        # Get the request user_email arg
        this_user_email = data.get("user_email")
        #print(this_user_password)
        # Return the serialized (by marshmallow schema) user
        return jsonify({"login_created" : my_login_set_service_g.create_login_set_for(this_user_name, this_user_password, this_user_email)}), 200

    # Update one user by id with password
    @app.route("/api/login_set/update", methods=["POST"])
    def update_login_set():
        data = request.get_json()
        # Get the request user_name arg
        this_user_name = data.get("user_name")
        # Get the request user_password arg
        this_user_password = data.get("user_password")
        # Get the request user_email arg
        this_user_email = data.get("user_email")
        # Return the serialized (by marshmallow schema) user
        return jsonify({"login_updated" : my_login_set_service_g.update_login_set_with(this_user_name, this_user_password, this_user_email)}), 200

    # Delete one user by id
    @app.route("/api/login_set/delete", methods=["POST"])
    def delete_login_set():
        data = request.get_json()
        # Get the request user_name arg
        this_user_name = data.get("user_name")
        # Return the serialized (by marshmallow schema) user
        return jsonify({"login_deleted" : my_login_set_service_g.delete_login_set_for(this_user_name)}), 200

    # Validate one user by id with password
    @app.route("/api/login_set/validate", methods=["POST"])
    def validate_login_set():
        data = request.get_json()
        #print("route create")
        #print(request.url)
        # Get the request user_name arg
        this_user_name = data.get("user_name")
        #print(this_user_name)
        # Get the request user_password arg
        this_user_password = data.get("user_password")
        #print(this_user_password)
        # Return the serialized (by marshmallow schema) user
        return jsonify({"login_validated" : my_login_set_service_g.validate_login_set(this_user_name, this_user_password)}), 200

    # Get a count of the data sets
    @app.route("/api/data_set/count", methods=["GET"])
    def count_data_set():
        return jsonify({"data_count" : my_data_set_service_g.count_data_set()}), 200

    # Finds a specific data_set by name, ignores privacy
    @app.route("/api/data_set/find/", methods=["GET"])
    def find_data_set():
        # Get the request this_data_set_name arg passed in query string
        this_data_set_name = request.args.get("data_set_name")
        # Return the serialized (by marshmallow schema) user
        return jsonify({"data_set_found" : my_data_set_service_g.find_data_set(this_data_set_name)}), 200

    # Grabs all the data_sets for user by name
    @app.route("/api/data_set/find_for/", methods=["GET"])
    def find_all_data_sets_for():
        # Get the request user_name arg
        this_user_name = request.args.get("user_name")
        # Return the serialized (by marshmallow schema) user
        return jsonify({"data_set_found" : my_data_set_service_g.find_all_data_sets_for(this_user_name)}), 200

    # Grabs all the not private data_sets
    @app.route("/api/data_set/find_all", methods=["GET"])
    def find_all_public_data_sets():
        # Return the serialized (by marshmallow schema) user
        return jsonify({"data_set_found" : my_data_set_service_g.find_all_public_data_sets()}), 200

    # Creates a specific data_set, if the user_name field is provided then create a user data set
    @app.route("/api/data_set/create/", methods=["GET"])
    @login_required
    def create_data_set():
        data = request.get_json()
        # Get the request data_set_name arg
        this_data_set_name = request.args.get("data_set_name")
        # Get the request file_size data
        this_file_size = data.get("file_size")
        # Get the request description data
        this_description = data.get("description")
        # Get the request data_set_url data
        this_data_set_url = data.get("data_set_url")
        # Get the request private data
        this_private = data.get("private")
        # Get the current user
        this_user_name = my_login_set_service_g.get_user_name_by_id(current_user.id)
        # Return the serialized (by marshmallow schema) user
        return jsonify({"data_set_created" : my_data_set_service_g.create_data_set_for(this_data_set_name, this_file_size, this_description, this_data_set_url, this_private, this_user_name)}), 200

    # Update one data_set
    @app.route("/api/data_set/update/", methods=["GET"])
    @login_required
    def update_data_set():
        data = request.get_json()
        # Get the request data_set_name arg
        this_data_set_name = request.args.get("data_set_name")
        # Get the request file_size data
        this_file_size = data.get("file_size")
        # Get the request description data
        this_description = data.get("description")
        # Get the request data_set_url data
        this_data_set_url = data.get("data_set_url")
        # Get the request private data
        this_private = data.get("private")
        # Get the current user
        this_user_name = my_login_set_service_g.get_user_name_by_id(current_user.id)
        # Return the serialized (by marshmallow schema) user
        return jsonify({"data_set_created" : my_data_set_service_g.update_data_set_with(this_data_set_name, this_file_size, this_description, this_data_set_url, this_private, this_user_name)}), 200

    # Delete one data_set
    @app.route("/api/data_set/delete/", methods=["GET"])
    @login_required
    def delete_data_set():
        # Get the request data_set_name arg
        this_data_set_name = request.args.get("data_set_name")
        # Get the current user
        this_user_name = my_login_set_service_g.get_user_name_by_id(current_user.id)
        # Return the serialized (by marshmallow schema) user
        return jsonify({"data_set_deleted" : my_data_set_service_g.delete_data_set_for(this_data_set_name, this_user_name)}), 200


    # Api route for a form login
    # Forms mean that the user and pass aren't exposed in the request url
    @app.route("/api/login", methods=["GET", "POST"])
    def login():
        # Ignore GETs, Ignore malformed forms. If the form has user_name ...
        form = request.get_json()
        if (request.method == "POST") and ("user_name" in form) and ("user_password" in form):
            # Grab the user_name
            this_user_name = form["user_name"]
            # Grab the user_password
            this_user_password = form["user_password"]
            # Check if login succeeds
            if my_login_set_service_g.validate_login_set(this_user_name, this_user_password):
                # Check if the user should be remembered
                remember = form.get("remember", "no") == "yes"
                # Should know the user exists, recheck anyways
                this_user_id = my_login_set_service_g.get_id(this_user_name)
                #print(this_user_id)
                if this_user_id:
                    this_user_active = my_login_set_service_g.get_user_active_by_id(this_user_id)
                    user_model = User(user_active = this_user_active)
                    user_model.id = this_user_id
                    if login_user(user_model, remember=remember):
                        # Return the login status
                        #print("login_user func suceeded")
                        return jsonify({"login": True})
                    else:
                        # Don't know why this would be false, some examples have this some don't
                        #print("login_user func failed")
                        return jsonify({"login": False})
                else:
                    #print("no id")
                    return jsonify({"login": False})
            else:
                # Bad info, let front end handle notifs
                #print("Bad login info!")
                return jsonify({"login": False})
        # Return false if the request is malformed
        #print("malformed login")
        return jsonify({"login": False})

    # Api route for reauth
    @app.route("/api/reauth", methods=["GET", "POST"])
    @login_required
    def reauth():
        # Only accept POSTs
        if request.method == "POST":
            confirm_login()
            return jsonify({"reauth": True})
        return jsonify({"reauth": False})

    # Api route for logout
    @app.route("/api/logout", methods=["GET", "POST"])
    @login_required
    def logout():
        if request.method == "POST":
            # We don't need any user info because we are logged in
            logout_user()
            return jsonify({"logout": True})
        else:
            # dont serve gets
            return jsonify({"reauth": False})

    # Fetch data for authenticated user
    @app.route("/api/session/user_name", methods=["GET"])
    @login_required
    def get_session_data():
        # Get the request user_name arg
        #print(current_user.id)
        this_user_name = my_login_set_service_g.get_user_name_by_id(current_user.id)
        # Could return any user specific data here
        return jsonify({"user_data" : "This is some private data for {}!".format(this_user_name)})

    # Check if a session exists on our flask server
    @app.route("/api/session/validate", methods=["GET"])
    def validate_session():
        if current_user.is_authenticated:
            return jsonify({"session": True})
        else:
            return jsonify({"session": False})

    # This is only needed if cross domain front and back ends
    # Leaving in just in case we go that route but,
    # the host should run both the front and back end concurrently
    # Get a csrf token
    @app.route("/api/csrf/get", methods=["GET"])
    def get_csrf():
        token = generate_csrf()
        response = jsonify({"detail": "CSRF cookie set"})
        response.headers.set("X-CSRFToken", token)
        return response

    return app

class TestLoginSet(unittest.TestCase):
    """
    Tester class for login sets
    https://flask.palletsprojects.com/en/1.1.x/reqcontext/
    To run the tests go to top level of flask app and run cmdline "python test_app.py"
    """
    # Create the test client adapter
    client = create_app().test_client()

    def test_empty_count(self):
        print("LOGINSET TEST CASE : TEST EMPTY COUNT")
        print("----------------------------------------------------------------------")
        # Test count
        print("[TEST] Test of empty count")

        response = json.loads(self.client.get(
            "/api/login_set/count", 
            method="GET",
        ).get_data())
        #print(response, type(response))
        self.assertEqual(response["login_count"], 0, "This should be 0 as the user has not been posted")
        print("----------------------------------------------------------------------")

    def test_empty_find(self):
        print("LOGINSET TEST CASE : TEST EMPTY FIND")
        print("----------------------------------------------------------------------")
        # Empty find
        print("[TEST] Test of empty find")

        response = json.loads(self.client.post(
            "/api/login_set/find", method="POST", 
            data=json.dumps({"user_name" : "username"}), 
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_found"], False, "This should be false as the user has not been posted")
        print("----------------------------------------------------------------------")

    def test_empty_delete(self):
        print("LOGINSET TEST CASE : TEST EMPTY DELETE")
        print("----------------------------------------------------------------------")
        # Test count
        print("[TEST] Test of empty count")

        response = json.loads(self.client.get(
            "/api/login_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["login_count"], 0, "This should be 0 as the user has not been posted")

        # Delete
        print("[TEST] Test of empty delete")

        response = json.loads(self.client.post(
            "/api/login_set/delete", method="POST", 
            data=json.dumps({"user_name" : "username"}), 
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_deleted"], False, "This should be false as the user has not been posted")
        print("----------------------------------------------------------------------")

    def test_create_and_delete(self):
        print("LOGINSET TEST CASE : TEST CREATE AND DELETE")
        print("----------------------------------------------------------------------")
        # Create
        print("[TEST] Test of create and find")

        response = json.loads(self.client.post(
            "/api/login_set/create", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password", "user_email" : "foo@bar.com"}), 
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_created"], True, "This should be true as this is first user post")

        # Test non-empty count
        print("[TEST] Test of non-empty count")

        response = json.loads(self.client.get(
            "/api/login_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["login_count"], 1, "This should be 1 as the user has been posted")

        # Test non-empty find
        print("[TEST] Test of non-empty find")

        response = json.loads(self.client.post(
            "/api/login_set/find", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}), 
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_found"], True, "This should be true as the user has been posted")

        # Delete and find
        print("[TEST] Test of delete")

        response = json.loads(self.client.post(
            "/api/login_set/delete", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}), 
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_deleted"], True, "This should be true as the user has been posted")

        # Test count after delete
        print("[TEST] Test of empty count after delete")

        response = json.loads(self.client.get(
            "/api/login_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["login_count"], 0, "This should be 0 as the user has not been posted")
        
        # Empty find after delete
        print("[TEST] Test of empty find after delete")

        response = json.loads(self.client.post(
            "/api/login_set/find", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}), 
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_found"], False, "This should be false as the user has not been posted")
        print("----------------------------------------------------------------------")

    def test_validate_and_update_and_delete(self):
        print("LOGINSET TEST CASE : TEST VALIDATE AND UPDATE AND DELETE")
        print("----------------------------------------------------------------------")
        # Create
        print("[TEST] Test of create and find")

        response = json.loads(self.client.post(
            "/api/login_set/create", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password", "user_email" : "foo@bar.com"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_created"], True, "This should be true as this is first user post")

        # Test non-empty count
        print("[TEST] Test of non-empty count")

        response = json.loads(self.client.get(
            "/api/login_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["login_count"], 1, "This should be 1 as the user been posted")

        # Test non-empty find
        print("[TEST] Test of non-empty find")

        response = json.loads(self.client.post(
            "/api/login_set/find", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_found"], True, "This should be true as the user has been posted")

        # Test validate correct
        print("[TEST] Test of validate with correct info")

        response = json.loads(self.client.post(
            "/api/login_set/validate", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_validated"], True, "This should be true as this is correct info")

        # Test validate incorrect
        print("[TEST] Test of validate with incorrect info")

        response = json.loads(self.client.post(
            "/api/login_set/validate", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "other_password"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_validated"], False, "This should be false as this is incorrect info")

        # Test bad update
        print("[TEST] Test of update with new bad info")

        response = json.loads(self.client.post(
            "/api/login_set/update", 
            method="POST", 
            data=json.dumps({"user_name" : "other_username", "user_password" : "other_password", "user_email" : "other_foo@bar.com"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_updated"], False, "This should be false as user posted and available for update but this is wrong user")

        # Retest validate correct
        print("[TEST] Retest of validate with correct info after bad update attempt")

        response = json.loads(self.client.post(
            "/api/login_set/validate", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_validated"], True, "This should be true as this is correct info")

        # Test update
        print("[TEST] Test of update with new info")

        response = json.loads(self.client.post(
            "/api/login_set/update", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "other_password", "user_email" : "foo@bar.com"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_updated"], True, "This should be true as user posted and available for update")

        # Test validate changed correct
        print("[TEST] Test of validate with updated correct info")

        response = json.loads(self.client.post(
            "/api/login_set/validate", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "other_password"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_validated"], True, "This should be true as this is now correct info")
        print("----------------------------------------------------------------------")

    def test_sessions(self):
        print("LOGINSET TEST CASE : TEST SESSIONS")
        print("----------------------------------------------------------------------")
        # Create
        print("[TEST] Test of create and find")

        response = json.loads(self.client.post(
            "/api/login_set/create", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password", "user_email" : "foo@bar.com"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_created"], True, "This should be true as this is first user post")

        # Test non-empty count
        print("[TEST] Test of non-empty count")

        response = json.loads(self.client.get(
            "/api/login_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["login_count"], 1, "This should be 1 as the user has been posted")

        # Test non-empty find
        print("[TEST] Test of non-empty find")

        response = json.loads(self.client.post(
            "/api/login_set/find", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_found"], True, "This should be true as the user has been posted")

        # Form session
        print("[TEST] Test of form session")

        response = json.loads(self.client.post(
            "/api/login", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login"], True, "This should be true as the user has been posted and session should be able to be made")

        # Validate session
        print("[TEST] Test of validate session")

        response = json.loads(self.client.get(
            "/api/session/validate", 
            method="GET",
        ).get_data())
        self.assertEqual(response["session"], True, "This should be true as the session has been made")

        # Reauth
        print("[TEST] Test of reform session")

        response = json.loads(self.client.post(
            "/api/reauth", 
            method="POST",
        ).get_data())
        self.assertEqual(response["reauth"], True, "This should be true as the session has been made")

        # Validate session
        print("[TEST] Test of validate session after reauth")

        response = json.loads(self.client.get(
            "/api/session/validate", 
            method="GET",
        ).get_data())
        self.assertEqual(response["session"], True, "This should be true as the session has been made")

        # Get private session data
        print("[TEST] Test of private session data api")

        response = json.loads(self.client.get(
            "/api/session/user_name", 
            method="GET",
        ).get_data())
        self.assertEqual(response["user_data"], "This is some private data for username!", "This should contain the user_name as plain text as well as some message")

        # Destroy session
        print("[TEST] Test of destroy session")

        response = json.loads(self.client.post(
            "/api/logout", 
            method="POST",
        ).get_data())
        self.assertEqual(response["logout"], True, "This should be true as the user has been posted and session should be able to be destroyed")

        # Validate session
        print("[TEST] Test of validate session")

        response = json.loads(self.client.get(
            "/api/session/validate", 
            method="GET",
        ).get_data())
        self.assertEqual(response["session"], False, "This should be false as the session has been destroyed")

        # Delete and find
        print("[TEST] Test of delete")

        response = json.loads(self.client.post(
            "/api/login_set/delete", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_deleted"], True, "This should be true as the user has been posted")

        # Test count after delete
        print("[TEST] Test of empty count after delete")

        response = json.loads(self.client.get(
            "/api/login_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["login_count"], 0, "This should be 0 as the user has not been posted")
        
        # Empty find after delete
        print("[TEST] Test of empty find after delete")

        response = json.loads(self.client.post(
            "/api/login_set/find", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_found"], False, "This should be false as the user has not been posted")
        print("----------------------------------------------------------------------")

class TestDataSet(unittest.TestCase):
    """
    Tester class for data sets
    https://flask.palletsprojects.com/en/1.1.x/reqcontext/
    To run the tests go to top level of flask app and run cmdline "python test_app.py"
    """
    # Create the test client adapter
    client = create_app().test_client()

    def test_empty_count(self):
        print("DATASET TEST CASE : TEST EMPTY COUNT")
        print("----------------------------------------------------------------------")
        # Test count
        print("[TEST] Test of empty count")

        response = json.loads(self.client.get(
            "/api/data_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["data_count"], 0, "This should be 0 as no data sets posted")
        print("----------------------------------------------------------------------")

    def test_empty_find(self):
        print("DATASET TEST CASE : TEST EMPTY FIND")
        print("----------------------------------------------------------------------")
        # Empty find
        print("[TEST] Test of empty find")

        response = json.loads(self.client.get(
            "/api/data_set/find/", method="GET", 
            query_string={"data_set_name" : "data_set_name"}, 
        ).get_data())
        self.assertEqual(response["data_set_found"] != "null", False, "This should be false as no data sets posted")
        print("----------------------------------------------------------------------")

    def test_empty_delete(self):
        print("DATASET TEST CASE : TEST EMPTY DELETE")
        print("----------------------------------------------------------------------")

        # Test count
        print("[TEST] Test of empty count")

        response = json.loads(self.client.get(
            "/api/data_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["data_count"], 0, "This should be 0 as no data sets posted")

        # Create
        print("[TEST] Test of create login")

        response = json.loads(self.client.post(
            "/api/login_set/create", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password", "user_email" : "foo@bar.com"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_created"], True, "This should be true as this is first user post")

        # Form session
        print("[TEST] Test of form session")

        response = json.loads(self.client.post(
            "/api/login", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login"], True, "This should be true as the user has been posted and session should be able to be made")

        # Validate session
        print("[TEST] Test of validate session")

        response = json.loads(self.client.get(
            "/api/session/validate", 
            method="GET",
        ).get_data())
        self.assertEqual(response["session"], True, "This should be true as the session has been made")

        # Delete
        print("[TEST] Test of empty delete")

        response = json.loads(self.client.get(
            "/api/data_set/delete/", method="GET", 
            query_string={"data_set_name" : "data_set_name"}, 
        ).get_data())
        self.assertEqual(response["data_set_deleted"], False, "This should be false as no data sets posted")

        # Destroy session
        print("[TEST] Test of destroy session")

        response = json.loads(self.client.post(
            "/api/logout", 
            method="POST",
        ).get_data())
        self.assertEqual(response["logout"], True, "This should be true as the user has been posted and session should be able to be destroyed")

        # Validate session
        print("[TEST] Test of validate session")

        response = json.loads(self.client.get(
            "/api/session/validate", 
            method="GET",
        ).get_data())
        self.assertEqual(response["session"], False, "This should be false as the session has been destroyed")

        # Delete
        print("[TEST] Test of delete login")

        response = json.loads(self.client.post(
            "/api/login_set/delete", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_deleted"], True, "This should be true as the user has been posted")

        print("----------------------------------------------------------------------")

    def test_create_and_delete(self):
        print("DATASET TEST CASE : TEST CREATE AND DELETE")
        print("----------------------------------------------------------------------")

        # Create
        print("[TEST] Test of create login")

        response = json.loads(self.client.post(
            "/api/login_set/create", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password", "user_email" : "foo@bar.com"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_created"], True, "This should be true as this is first user post")

        # Form session
        print("[TEST] Test of form session")

        response = json.loads(self.client.post(
            "/api/login", 
            method="POST", 
            data=json.dumps({"user_name" : "username", "user_password" : "password"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login"], True, "This should be true as the user has been posted and session should be able to be made")

        # Validate session
        print("[TEST] Test of validate session")

        response = json.loads(self.client.get(
            "/api/session/validate", 
            method="GET",
        ).get_data())
        self.assertEqual(response["session"], True, "This should be true as the session has been made")

        # Create
        print("[TEST] Test of create and find")

        response = json.loads(self.client.get(
            "/api/data_set/create/", 
            method="GET", 
            query_string={"data_set_name" : "data_set_name"}, 
            data=json.dumps({"file_size" : "file_size", "description" : "description", "data_set_url" : "https://www.data_set_url.com", "private" : False}), 
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["data_set_created"], True, "This should be true as this is data_set")

        # Test non-empty count
        print("[TEST] Test of non-empty count")

        response = json.loads(self.client.get(
            "/api/data_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["data_count"], 1, "This should be 1 as we just created data_set")

        # Non-empty find
        print("[TEST] Test of non-empty find")

        response = json.loads(self.client.get(
            "/api/data_set/find/", method="GET", 
            query_string={"data_set_name" : "data_set_name"}, 
        ).get_data())
        #print(response)
        self.assertEqual(response["data_set_found"] != "null", True, "This should be true as data set posted")

        # Delete and find
        print("[TEST] Test of delete")

        response = json.loads(self.client.get(
            "/api/data_set/delete/", method="GET", 
            query_string={"data_set_name" : "data_set_name"}, 
        ).get_data())
        self.assertEqual(response["data_set_deleted"], True, "This should be true as data sets posted")

        # Test count after delete
        print("[TEST] Test of empty count after delete")

        response = json.loads(self.client.get(
            "/api/data_set/count", 
            method="GET",
        ).get_data())
        self.assertEqual(response["data_count"], 0, "This should be 0 as no data sets posted after delete")
        
        # Empty find after delete
        print("[TEST] Test of empty find after delete")

        response = json.loads(self.client.get(
            "/api/data_set/find/", method="GET", 
            query_string={"data_set_name" : "data_set_name"}, 
        ).get_data())
        self.assertEqual(response["data_set_found"] != "null", False, "This should be false as no data sets posted after delete")
        
        # Destroy session
        print("[TEST] Test of destroy session")

        response = json.loads(self.client.post(
            "/api/logout", 
            method="POST",
        ).get_data())
        self.assertEqual(response["logout"], True, "This should be true as the user has been posted and session should be able to be destroyed")

        # Validate session
        print("[TEST] Test of validate session")

        response = json.loads(self.client.get(
            "/api/session/validate", 
            method="GET",
        ).get_data())
        self.assertEqual(response["session"], False, "This should be false as the session has been destroyed")
        
        # Delete
        print("[TEST] Test of delete login")

        response = json.loads(self.client.post(
            "/api/login_set/delete", 
            method="POST", 
            data=json.dumps({"user_name" : "username"}),
            content_type='application/json',
        ).get_data())
        self.assertEqual(response["login_deleted"], True, "This should be true as the user has been posted")

        print("----------------------------------------------------------------------")

if __name__ == '__main__':
    unittest.main()
