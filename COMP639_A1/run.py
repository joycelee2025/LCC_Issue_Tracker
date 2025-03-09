"""This script provides an easy way to run our "Login Example" app.

There are many ways to run a Flask app, and not all of them require run.py.
When running locally, you can use any of the following approaches:

    - Execute this run.py script in Python to start your web app. You could:
        - Open run.py in Visual Studio Code, open the "Run" menu, then select
            "Start Debugging" (or press F5). This only works if you don't have
            a custom launch.json file (see below).
        - Open run.py in Visual Studio Code, right-click anywhere in the code
            editor, select "Run Python", then select "Run Python File in
            Terminal". This works whether or not you have a custom launch.json
            file (see below).
        - From the terminal, type `python run.py`.

    - To simplify running your web app during development, you can create a
        custom launch.json file in Visual Studio Code. This runs your app
        whenever you choose Run/Start Debugging or press F5, regardless of what
        source file you're currently editing. This method doesn't use run.py.
        - Go to the "Run and Debug" tab in the sidebar.
        - Click the link to "create a launch.json file".
        - Select "More Python Debugger options..." from the menu that appears.
        - Choose "Python Debugger: Flask LoginExample".
        - Save the new launch.json file.

    - You can run your Flask app directly from the command line. However,
        you'll need to specify the app to run. For example, to run `loginapp`
        you'll need to enter `python -m flask --app loginapp run`. This method
        doesn't use run.py.
        
On PythonAnywhere and similar WSGI servers, you can do either of the following
in your WSGI configuration file:

    - Import the `app` object from run.py. For example, in PythonAnywhere's
        WSGI file, set the final line to `from run import app as application`.

    - Import the `app` object directly from the `loginapp` module. For example,
        in PythonAnywhere's WSGI file, set the final line to `from loginapp
        import app as application`. This method doesn't require run.py.

Because there are so many ways to start a Python/Flask web app, and many of
them bypass run.py entirely, don't put any of your application code in here.
Think of run.py as a "shortcut" or "launcher" used to run your Flask app,
rather than a core part of the app itself.
"""
from LCCapp import app

# If run.py was actually executed (run), not just imported into another script,
# then start our Flask app on a local development server. To learn more about
# how we check for this, refer to https://realpython.com/if-name-main-python/.
if __name__ == "__main__":
    app.run(debug=True)