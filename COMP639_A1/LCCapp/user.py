from LCCapp import app
from LCCapp import db
from flask import redirect, render_template, request, session, url_for, flash
from flask_bcrypt import Bcrypt
import re
from werkzeug.utils import secure_filename
import os
import datetime

CurrentTime = datetime.datetime.now()

flask_bcrypt = Bcrypt(app)

#defaults
DEFAULT_USER_ROLE = 'visitor'
DEFAULT_USER_STATUS = 'active'
DEFAULT_ISSUE_STATUS = 'new'

#define upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')

def user_home_url():
    """Generates a URL to the homepage for the currently logged-in user.
    
    If the user is not logged in, or the role stored in their session cookie is
    invalid, this returns the URL for the login page instead."""
    role = session.get('role', None)

    if role=='visitor':
        home_endpoint='visitor_home'
    elif role=='helper':
        home_endpoint='helper_home'
    elif role=='admin':
        home_endpoint='admin_home'
    else:
        home_endpoint = 'login'
    
    return url_for(home_endpoint)

@app.route('/')
def root():
    """Root endpoint (/)
    
    Methods:
    - get: Redirects guests to the login page, and redirects logged-in users to
        their own role-specific homepage.
    """
    return redirect(user_home_url())

@app.route('/home')
def home():
    """Home page endpoint.

    Methods:
    - get: Redirects guests to the login page, and redirects logged-in users to
        their own role-specific homepage.
    """
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page endpoint.

    Methods:
    - get: Renders the login page.
    - post: Attempts to log the user in using the credentials supplied via the
        login form, and either:
        - Redirects the user to their role-specific homepage (if successful)
        - Renders the login page again with an error message (if unsuccessful).
    
    If the user is already logged in, both get and post requests will redirect
    to their role-specific homepage.
    """
    if 'loggedin' in session:
         return redirect(user_home_url())

    if request.method=='POST' and 'username' in request.form and 'password' in request.form:
        # Get the login details submitted by the user.
        username = request.form['username']
        password = request.form['password']

        # Attempt to validate the login details against the database.
        with db.get_cursor() as cursor:
            # Try to retrieve the account details for the specified username.
            #
            # Note: we use a Python multiline string (triple quote) here to
            # make the query more readable in source code. This is just a style
            # choice: the line breaks are ignored by MySQL, and it would be
            # equally valid to put the whole SQL statement on one line like we
            # do at the beginning of the `signup` function.
            cursor.execute('''
                           SELECT user_id, username, password_hash, role
                           FROM users
                           WHERE username = %s;
                           ''', (username,))
            account = cursor.fetchone()
            
            if account is not None:
                # We found a matching account: now we need to check whether the
                # password they supplied matches the hash in our database.
                password_hash = account['password_hash']
                
                if flask_bcrypt.check_password_hash(password_hash, password):
                    # Password is correct. Save the user's ID, username, and role
                    # as session data, which we can access from other routes to
                    # determine who's currently logged in.
                    # 
                    # Users can potentially see and edit these details using their
                    # web browser. However, the session cookie is signed with our
                    # app's secret key. That means if they try to edit the cookie
                    # to impersonate another user, the signature will no longer
                    # match and Flask will know the session data is invalid.
                    session['loggedin'] = True
                    session['user_id'] = account['user_id']
                    session['username'] = account['username']
                    session['role'] = account['role']

                    return redirect(user_home_url())
                else:
                    # Password is incorrect. Re-display the login form, keeping
                    # the username provided by the user so they don't need to
                    # re-enter it. We also set a `password_invalid` flag that
                    # the template uses to display a validation message.
                    return render_template('login.html',
                                           username=username,
                                           password_invalid=True)
            else:
                # We didn't find an account in the database with this username.
                # Re-display the login form, keeping the username so the user
                # can see what they entered (otherwise, they might just keep
                # trying the same thing). We also set a `username_invalid` flag
                # that tells the template to display an appropriate message.
                #
                # Note: In this example app, we tell the user if the user
                # account doesn't exist. Many websites (e.g. Google, Microsoft)
                # do this, but other sites display a single "Invalid username
                # or password" message to prevent an attacker from determining
                # whether a username exists or not. Here, we accept that risk
                # to provide more useful feedback to the user.
                return render_template('login.html', 
                                       username=username,
                                       username_invalid=True)

    # This was a GET request, or an invalid POST (no username and/or password),
    # so we just render the login form with no pre-populated details or flags.
    return render_template('login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    """Signup (registration) page endpoint.

    Methods:
    - get: Renders the signup page.
    - post: Attempts to create a new user account using the details supplied
        via the signup form, then renders the signup page again with a welcome
        message (if successful) or one or more error message(s) explaining why
        signup could not be completed.

    If the user is already logged in, both get and post requests will redirect
    to their role-specific homepage.
    """
    if 'loggedin' in session:
         return redirect(user_home_url())
    
    if request.method == 'POST' and 'username' in request.form and 'email' in request.form and 'password' in request.form and 'confirm_password' in request.form and 'first_name' in request.form and 'last_name' in request.form and 'location' in request.form:
        # Get the details submitted via the form on the signup page, and store
        # the values in temporary local variables for ease of access.
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        location = request.form['location']
        profile_image = request.files['profile_image']

        # We start by assuming that everything is okay. If we encounter any
        # errors during validation, we'll store an error message in one or more
        # of these variables so we can pass them through to the template.
        username_error = None
        email_error = None
        password_error = None
        confirm_password_error = None
        first_name_error = None
        last_name_error = None
        location_error = None

        # Check whether there's an account with this username in the database.
        with db.get_cursor() as cursor:
            cursor.execute('SELECT user_id FROM users WHERE username = %s;',
                           (username,))
            account_already_exists = cursor.fetchone() is not None
        
        # Validate the username, ensuring that it's unique (as we just checked
        # above) and meets the naming constraints of our web app.
        if account_already_exists:
            username_error = 'An account already exists with this username.'
        elif len(username) > 20:
            # The user should never see this error during normal conditions,
            # because we set a maximum length of 20 on the input field in the
            # template. However, a user or attacker could easily override that
            # and submit a longer value, so we need to handle that case.
            username_error = 'Your username cannot exceed 20 characters.'
        elif not re.match(r'[A-Za-z0-9]+', username):
            username_error = 'Your username can only contain letters and numbers.'            

        # Validate the new user's email address. Note: The regular expression
        # we use here isn't a perfect check for a valid address, but is
        # sufficient for this example.
        if len(email) > 320:
            # As above, the user should never see this error under normal
            # conditions because we set a maximum input length in the template.
            email_error = 'Your email address cannot exceed 320 characters.'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            email_error = 'Invalid email address.'
                
        # Validate password. Think about what other constraints might be useful
        # here for security (e.g. requiring a certain mix of character types,
        # or avoiding overly-common passwords). Make sure that you clearly
        # communicate any rules to the user, either through hints on the signup
        # page or with clear error messages here.
        #
        # Note: Unlike the username and email address, we don't enforce a
        # maximum password length. Because we'll be storing a hash of the
        # password in our database, and not the password itself, it doesn't
        # matter how long a password the user chooses. Whether it's 8 or 800
        # characters, the hash will always be the same length.
        if len(password) < 8:
            password_error = 'Please choose a longer password!'
        elif not re.match(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$', password):
            password_error = 'Password must contain at least one number, one lowercase letter, and one uppercase letter.'

        if password != confirm_password:
            confirm_password_error = 'Passwords do not match.'

        if len(first_name) > 50:
            first_name_error = 'Your first name cannot exceed 50 characters.'

        if len(last_name) > 50:
            last_name_error = 'Your last name cannot exceed 50 characters.'

        if len(location) > 50:
            location_error = 'Your location cannot exceed 50 characters.'

        if (username_error or email_error or password_error or confirm_password_error or first_name_error or last_name_error or location_error):
            # One or more errors were encountered, so send the user back to the
            # signup page with their username and email address pre-populated.
            # For security reasons, we never send back the password they chose.
            return render_template('signup.html',
                                   username=username,
                                   email=email,
                                   first_name=first_name,
                                   last_name=last_name,
                                   location=location,
                                   username_error=username_error,
                                   email_error=email_error,
                                   password_error=password_error,
                                   confirm_password_error=confirm_password_error,
                                   first_name_error=first_name_error,
                                   last_name_error=last_name_error,
                                   location_error=location_error)
        else:

            password_hash = flask_bcrypt.generate_password_hash(password)
            
            if 'profile_image' in request.files and profile_image.filename:
                filename = secure_filename(profile_image.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                profile_image.save(filepath)

            else:
                filename = 'default.jpg'

            with db.get_cursor() as cursor:
                cursor.execute('''
                               INSERT INTO users (username, password_hash, email, first_name, last_name, location, profile_image, role, status)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                               ''',
                               (username, password_hash, email, first_name, last_name, location, filename, DEFAULT_USER_ROLE, DEFAULT_USER_STATUS))
            
            return render_template('signup.html', signup_successful=True)            

    # This was a GET request, or an invalid POST (no username, email, and/or
    # password). Render the signup page with no pre-populated form fields or
    # error messages.
    return render_template('signup.html')

@app.route('/profile')
def profile():
    """User Profile page endpoint.

    Methods:
    - get: Renders the user profile page for the current user.

    If the user is not logged in, requests will redirect to the login page.
    """
    if 'loggedin' not in session:
         return redirect(url_for('login'))

    # Retrieve user profile from the database.
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

    return render_template('profile.html', profile=profile)

@app.route('/profile/user-list')
def users_list():
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    if session['role'] not in ['admin']:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(user_home_url())
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT user_id, username, email, first_name, last_name, location, profile_image, role, status FROM users;')
        users = cursor.fetchall()

        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

    search = request.args.get('search')
    if search:
        with db.get_cursor() as cursor:
            cursor.execute('SELECT user_id, username, email, first_name, last_name, location, profile_image, role, status FROM users WHERE username LIKE %s OR email LIKE %s OR first_name LIKE %s OR last_name LIKE %s OR location LIKE %s;',
                           (f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'))
            users = cursor.fetchall()

    return render_template('users_list.html', users=users, profile=profile)

@app.route('/profile/user-list/view/<int:user_id>')
def view_user(user_id):
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    if session['role'] not in ['admin']:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(user_home_url())
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT user_id, username, email, first_name, last_name, location, profile_image, role, status FROM users WHERE user_id = %s;',
                       (user_id,))
        user = cursor.fetchone()

        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

    return render_template('users_view.html', user=user, profile=profile, user_id=user_id)

@app.route('/profile/user-list/view/<int:user_id>/update-role', methods=['GET', 'POST'])
def user_role(user_id):
    if 'loggedin' not in session:
            return redirect(url_for('login'))
    
    if session['role'] not in ['admin']:
        flash('You do not have permission to update this user.', 'danger')
        return redirect(url_for('view_user', user_id=user_id))
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT user_id, username, email, first_name, last_name, location, profile_image, role, status FROM users WHERE user_id = %s;',
                       (user_id,))
        user = cursor.fetchone()

        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

    if request.method == 'POST' and 'role' in request.form:
        new_role = request.form['role']

        with db.get_cursor() as cursor:
            cursor.execute('''UPDATE users SET role = %s WHERE user_id = %s;''',
                           (new_role, user_id))
        
            flash('User role updated successfully.', 'success')

        return redirect(url_for('view_user', user_id=user_id))
    
    return render_template('users_view.html', user=user, profile=profile)

@app.route('/profile/user-list/view/<int:user_id>/update-status', methods=['GET', 'POST'])
def user_status(user_id):
    if 'loggedin' not in session:
            return redirect(url_for('login'))
    
    if session['role'] not in ['admin']:
        flash('You do not have permission to update this user.', 'danger')
        return redirect(url_for('view_user', user_id=user_id))
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT user_id, username, email, first_name, last_name, location, profile_image, role, status FROM users WHERE user_id = %s;',
                       (user_id,))
        user = cursor.fetchone()

        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

    if request.method == 'POST' and 'status' in request.form:
        new_status = request.form['status']

        with db.get_cursor() as cursor:
            cursor.execute('''UPDATE users SET status = %s WHERE user_id = %s;''',
                           (new_status, user_id))
            flash('User status updated successfully.', 'success')

        return redirect(url_for('view_user', user_id=user_id))
    
    return render_template('users_view.html', user=user, profile=profile)

@app.route('/profile/my-details', methods=['GET', 'POST'])
def my_details():
    if 'loggedin' not in session:
         return redirect(url_for('login'))

    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

    if request.method == 'POST' and 'username' in request.form and 'email' in request.form and 'first_name' in request.form and 'last_name' in request.form and 'location' in request.form:
        new_email = request.form['email']
        new_first_name = request.form['first_name']
        new_last_name = request.form['last_name']
        new_location = request.form['location']
        new_profile_image = request.files['new_profile_image']

        email_error = None
        password_error = None
        first_name_error = None
        last_name_error = None
        location_error = None

        if len(new_email) > 320:
            email_error = 'Your email address cannot exceed 320 characters.'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', new_email):
            email_error = 'Invalid email address.'

        if len(new_first_name) > 50:
            first_name_error = 'Your first name cannot exceed 50 characters.'

        if len(new_last_name) > 50:
            last_name_error = 'Your last name cannot exceed 50 characters.'

        if len(new_location) > 50:
            location_error = 'Your location cannot exceed 50 characters.'

        if (email_error or password_error or first_name_error or last_name_error or location_error):
            return render_template('my_details.html',
                                   profile=profile,
                                   email_error=email_error,
                                   password_error=password_error,
                                   first_name_error=first_name_error,
                                   last_name_error=last_name_error,
                                   location_error=location_error)
        else:
            if 'new_profile_image' in request.files and new_profile_image.filename:
                new_filename = secure_filename(new_profile_image.filename)
                new_filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                new_profile_image.save(new_filepath)

                profile['profile_image'] = new_filename

                with db.get_cursor() as cursor:
                    cursor.execute('''
                                UPDATE users SET profile_image = %s WHERE user_id = %s;''',
                                (new_filename, session['user_id']))
         
            with db.get_cursor() as cursor:
                cursor.execute('''
                            UPDATE users
                            SET email = %s, first_name = %s, last_name = %s, location = %s
                            WHERE user_id = %s;
                            ''',
                            (new_email, new_first_name, new_last_name, new_location, session['user_id']))
                
        # Update the profile variable with the new details so that the template
        # can display them.
        profile['email'] = new_email
        profile['first_name'] = new_first_name
        profile['last_name'] = new_last_name
        profile['location'] = new_location

        return render_template('my_details.html', profile=profile, update_successful=True)

    return render_template('my_details.html', profile=profile)

@app.route('/profile/my-password', methods=['GET', 'POST'])
def my_password():
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role, password_hash FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()
        password_hash = profile['password_hash']

    if request.method == 'POST' and 'current_password' in request.form and 'new_password' in request.form and 'confirm_password' in request.form:
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        current_password_error = None
        new_password_error = None
        confirm_password_error = None

        if not flask_bcrypt.check_password_hash(password_hash, current_password):
            current_password_error = 'Incorrect password.'

        if len(new_password) < 8:
            new_password_error = 'Please choose a longer password!'
        elif not re.match(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$', new_password):
            new_password_error = 'Password must contain at least one number, one lowercase letter, and one uppercase letter.'

        if new_password != confirm_password:
            confirm_password_error = 'Passwords do not match.'

        if (current_password_error or new_password_error or confirm_password_error):
            return render_template('my_password.html',
                                   profile=profile,
                                   current_password_error=current_password_error,
                                   new_password_error=new_password_error,
                                   confirm_password_error=confirm_password_error)
        else:
            new_password_hash = flask_bcrypt.generate_password_hash(new_password)

            with db.get_cursor() as cursor:
                cursor.execute('''
                            UPDATE users
                            SET password_hash = %s
                            WHERE user_id = %s;
                            ''',
                            (new_password_hash, session['user_id']))
                
            return render_template('profile.html', profile=profile, update_successful=True)
        
    return render_template('my_password.html', profile=profile)
    
@app.route('/profile/my-issues')
def my_issues():
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                (session['user_id'],))
        profile = cursor.fetchone()
    
        if session['role'] in ['helper', 'admin']:
            cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues;')
            issue = cursor.fetchall()

        else:
            cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues WHERE user_id = %s;',
                    (session['user_id'],))
            issue = cursor.fetchall()
        
    return render_template('my_issues.html', issue=issue, profile=profile)

@app.route('/profile/my-issues/resolved')
def resolved_issues():
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    if session['role'] not in ['helper', 'admin']:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(user_home_url())
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                (session['user_id'],))
        profile = cursor.fetchone()

        if session['role'] in ['helper', 'admin']:
            cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues WHERE status = "resolved";')
            issue = cursor.fetchall()
  
    return render_template('resolved_issues.html', issue=issue, profile=profile)

@app.route('/profile/my-issues/unresolved')
def unresolved_issues():
    if 'loggedin' not in session:
            return redirect(url_for('login'))
    
    if session['role'] not in ['helper', 'admin']:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(user_home_url())
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                (session['user_id'],))
        profile = cursor.fetchone()

        if session['role'] in ['helper', 'admin']:
            cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues WHERE status != "resolved";')
            issue = cursor.fetchall()

    return render_template('unresolved_issues.html', issue=issue, profile=profile)

@app.route('/profile/my-issues/view/<int:issue_id>')
def view_issue(issue_id):
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    with db.get_cursor() as cursor:
        if session['role'] in ['helper', 'admin']:
            cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues WHERE issue_id = %s;',
                           (issue_id,))
            issue = cursor.fetchone()
        else:
            cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues WHERE user_id = %s AND issue_id = %s;',
                        (session['user_id'], issue_id))
            issue = cursor.fetchone()

        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

        cursor.execute('SELECT issues.issue_id, users.username, users.role FROM issues JOIN users ON issues.user_id = users.user_id WHERE issue_id = %s;',
                       (issue_id,))
        issue_user = cursor.fetchone()

        cursor.execute('''SELECT comments.comment_id, comments.content, comments.created_at, 
        users.username, users.role, users.profile_image 
        FROM comments JOIN users ON comments.user_id = users.user_id WHERE comments.issue_id = %s;''',
        (issue_id,))
        comments = cursor.fetchall()

    return render_template('issue_view.html', issue=issue, profile=profile, comments=comments, issue_user=issue_user) 
    
@app.route('/profile/my-issues/view/<int:issue_id>/update-status', methods=['GET', 'POST'])
def update_status(issue_id):
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    if session['role'] not in ['admin', 'helper']:
        flash('You do not have permission to update the status of this issue.', 'danger')
        return redirect(url_for('view_issue', issue_id=issue_id))
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

        cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues WHERE user_id = %s AND issue_id = %s;',
                       (session['user_id'], issue_id))
        issue = cursor.fetchone()
    
    if request.method == 'POST' and 'status' in request.form:
        new_status = request.form['status']

        with db.get_cursor() as cursor:
            cursor.execute('''UPDATE issues SET status = %s WHERE issue_id = %s;''',
                           (new_status, issue_id))
            flash('Issue status updated successfully.', 'success')

        return redirect(url_for('view_issue', issue_id=issue_id))
    
    return render_template('issue_view.html', profile=profile)

@app.route('/profile/my-issues/view/<int:issue_id>/comment', methods=['GET', 'POST'])
def add_comment(issue_id):
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()

        cursor.execute('SELECT issue_id, summary, description, status, created_at FROM issues WHERE user_id = %s AND issue_id = %s;',
                       (session['user_id'], issue_id))
        issue = cursor.fetchone()

    if request.method == 'POST' and 'content' in request.form:
        content = request.form['content']

        content_error = None

        if len(content) > 300:
            content_error = 'Your comment cannot exceed 300 characters.'

        if content_error:
            return render_template('issue_view.html', content=content, content_error=content_error)
        else:
            with db.get_cursor() as cursor:
                cursor.execute('''INSERT INTO comments (user_id, issue_id, content, created_at) VALUES (%s, %s, %s, %s);''',
                               (session['user_id'], issue_id, content, CurrentTime))
                flash('Comment added successfully.', 'success')                

            if profile['role'] in ['helper', 'admin']:
                with db.get_cursor() as cursor:
                    cursor.execute('''UPDATE issues SET status = 'open' WHERE issue_id = %s;''', (issue_id,))
                    flash('Issue status updated to open.', 'success')

            return redirect(url_for('view_issue', issue_id=issue_id))
        
    return render_template('issue_view.html', profile=profile)

@app.route('/profile/my-issues/add', methods=['GET', 'POST'])
def add_issue():
    if 'loggedin' not in session:
         return redirect(url_for('login'))
    
    with db.get_cursor() as cursor:
        cursor.execute('SELECT username, email, first_name, last_name, location, profile_image, role FROM users WHERE user_id = %s;',
                       (session['user_id'],))
        profile = cursor.fetchone()
    
    if request.method == 'POST' and 'summary' in request.form and 'description' in request.form:
        summary = request.form['summary']
        description = request.form['description']

        summary_error = None
        description_error = None
        
        if len(summary) > 100:
            summary_error = 'Your summary cannot exceed 100 characters.'

        if len(description) > 300:
            description_error = 'Your description cannot exceed 500 characters.'
        
        if (summary_error or description_error):
            return render_template('issue_add.html',
                                   summary=summary,
                                   description=description,
                                   summary_error=summary_error,
                                   description_error=description_error)
        else:
            with db.get_cursor() as cursor:
                cursor.execute('''
                            INSERT INTO issues (user_id, summary, description, created_at, status)
                            VALUES (%s, %s, %s, %s, %s);
                            ''',
                            (session['user_id'], summary, description, CurrentTime, DEFAULT_ISSUE_STATUS))
                
            flash('Issue added successfully.', 'success')
            return redirect(url_for('my_issues'))
        
    return render_template('issue_add.html', profile=profile)	

@app.route('/logout')
def logout():
    """Logout endpoint.

    Methods:
    - get: Logs the current user out (if they were logged in to begin with),
        and redirects them to the login page.
    """
    # Note that nothing actually happens on the server when a user logs out: we
    # just remove the cookie from their web browser. They could technically log
    # back in by manually restoring the cookie we've just deleted. In a high-
    # security web app, you may need additional protections against this (e.g.
    # keeping a record of active sessions on the server side).
    session.pop('loggedin', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    
    return redirect(url_for('login'))


