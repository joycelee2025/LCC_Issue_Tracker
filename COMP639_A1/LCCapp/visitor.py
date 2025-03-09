from LCCapp import app
from LCCapp import db
from flask import redirect, render_template, session, url_for

@app.route('/visitor/home')
def visitor_home():
     """visitor Homepage endpoint.

     Methods:
     - get: Renders the homepage for the current visitor, or an "Access
          Denied" 403: Forbidden page if the current user has a different role.

     If the user is not logged in, requests will redirect to the login page.
     """
     # Note: You'll need to use "logged in" and role checks like the ones below
     # on every single endpoint that should be restricted to logged-in users,
     # or users with a certain role. Otherwise, anyone who knows the URL can
     # access that page.
     #
     # In this example we've just repeated the code everywhere (you'll see the
     # same checks in staff.py and admin.py), but it would be a great idea to
     # extract these checks into reusable functions. You could place them in
     # user.py with the rest of the login system, for example, and import them
     # into other modules as necessary.
     #
     # One common way to implement login and role checks in Flask is with "View
     # Decorators", such as the "login_required" example in the official
     # tutorial [1]. If you choose to use that approach, you'll need to adapt
     # it a little to our project, as we don't store the username in `g.user`.
     #
     # References:
     # [1] https://flask.palletsprojects.com/en/stable/patterns/viewdecorators/

     if 'loggedin' not in session:
          # The user isn't logged in, so redirect them to the login page.
          return redirect(url_for('login'))
     elif session['role']!='visitor':
          # The user isn't logged in with a visitor account, so return an
          # "Access Denied" page instead. We don't do a redirect here, because
          # we're not sending them somewhere else: just delivering an
          # alternative page.
          # 
          # Note: the '403' below returns HTTP status code 403: Forbidden to the
          # browser, indicating that the user was not allowed to access the
          # requested page.
          return render_template('access_denied.html'), 403

     # The user is logged in with a visitor account, so render the visitor
     # homepage as requested.
     return render_template('visitor_home.html')