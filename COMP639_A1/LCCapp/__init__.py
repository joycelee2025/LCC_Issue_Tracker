# This script runs automatically when our `loginapp` module is first loaded,
# and handles all the setup for our Flask app.
from flask import Flask

app = Flask(__name__)

# Set the "secret key" that our app will use to sign session cookies. This can
# be anything.
# 
# Anyone with access to this key can pretend to be signed in as any user. In a
# real-world project, you wouldn't store this key in your source code. To learn
# about how to manage "secrets" like this in production code, check out
# https://blog.gitguardian.com/how-to-handle-secrets-in-python/
#
# For the purpose of your assignments, you DON'T need to use any of those more
# advanced and secure methods: it's fine to store your secret key in your
# source code like we do here.
app.secret_key = 'Example Secret Key (CHANGE THIS TO YOUR OWN SECRET KEY!)'

# Set up database connection.
from LCCapp import connect
from LCCapp import db
db.init_db(app, connect.dbuser, connect.dbpass, connect.dbhost, connect.dbname)

# Include all modules that define our Flask route-handling functions.
from LCCapp import user
from LCCapp import visitor
from LCCapp import helper
from LCCapp import admin