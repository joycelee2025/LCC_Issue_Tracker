"""Defines the MySQL database connection details for this app.

These are stored in their own file so you can have separate versions for each
environment your app runs in (e.g. one for your local development environment,
and one for PythonAnywhere). If you're working in a team, each team member will
likely need their own version of connect.py.

Exclude this file from GitHub, otherwise you won't be able to have a different
version on each system.

For your local MySQL instance:
- Username (`dbuser`), Host (`dbhost`), and Port (`dbport`) can be found on the
    MySQL Workbench home screen.
- Password (`dbpass`) is whatever you set up during installation.
- Database name (`dbname`) is the name of the database you created for this app
    (e.g. "loginexample").

On PythonAnywhere:
- Username (`dbuser`) and Host (`dbhost`) are shown on the Databases tab.
- Port (`dbport`) is 3306 (the default MySQL port).
- Password (`dbpass`) is whatever you chose in the "MySQL password" section of
    the Databases tab. You can't see what the current password is, so if you've
    forgotten it you'll need to set a new one.
- Database name (`dbname`) is the name of the database you created for this app
    on PythonAnywhere. It will be listed in the "Your databases" section of the
    Databases tab. Don't forget that PythonAnywhere databases start with your
    username + "$". For example, if your username is "user1234" and you named
    your database "loginexample" then your full database name will be
    "user1234$loginexample".
"""
dbuser = 'root'  # PUT YOUR USERNAME HERE - usually "root"
dbpass = '1234'  # PUT YOUR PASSWORD HERE
dbhost = 'localhost'
dbport = '3306'
dbname = 'LCCapp'  # PUT YOUR DATABASE NAME HERE