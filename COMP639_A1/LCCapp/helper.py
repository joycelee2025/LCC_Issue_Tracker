from LCCapp import app
from LCCapp import db
from flask import redirect, render_template, session, url_for

@app.route('/helper/home')
def helper_home():
     """helper Homepage endpoint.

     Methods:
     - get: Renders the homepage for the current helper user, or an "Access
          Denied" 403: Forbidden page if the current user has a different role.

     If the user is not logged in, requests will redirect to the login page.
     """
     if 'loggedin' not in session:
          return redirect(url_for('login'))
     elif session['role']!='helper':
          return render_template('access_denied.html'), 403

     return render_template('helper_home.html')