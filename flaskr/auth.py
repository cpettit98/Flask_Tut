"""A view function is the code you write to respond to requests to your application. 
Flask uses patterns to match the incoming request URL to the view that should handle it. 
The view returns data that Flask turns into an outgoing response. Flask can also go the 
other direction and generate a URL to a view based on its name and arguments.

A Blueprint is a way to organize a group of related views and other code. Rather than
registering views and other code directly with an application, they are registered with 
a blueprint. Then the blueprint is registered with the application when it is available 
in the factory function.

"""


import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db
# When using a blueprint, the name of the blueprint is prepended to the name of the function, 
# so the endpoint for the login function you wrote above is 'auth.login' because you added it 
# to the 'auth' blueprint.

bp = Blueprint('auth', __name__, url_prefix='/auth')

# bp.route assocaites the URL/register with the register view function 
@bp.route('/register', methods=('GET', 'POST'))
def register():
    # If the user submitted the form, request.method will be 'POST'
    # Start validating the input 
    if request.method == 'POST':
        # request.form is a dict mapping cubmitted form keys and values. 
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                # insert info into our database (hashed password for security)
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                #save changes
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                # Generates the URL for login based on its name
                # that way if you change it - dont need to change the code 
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        # Returns one row from the query
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

# registers a function that runs before the view function, no matter what URL is requested.
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

# To logout, remove user id from the session
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# This decorator returns a new view function that wraps the original view it’s applied to. 
# The new function checks if a user is loaded and redirects to the login page otherwise. 
# If a user is loaded the original view is called and continues normally.
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view