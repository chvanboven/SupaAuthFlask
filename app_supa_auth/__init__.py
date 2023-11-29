from gotrue.errors import AuthApiError
import functools
from dotenv import load_dotenv
import os
from supabase import create_client

from flask import (
    Flask,
    session,
    render_template,
    request,
    abort,
    flash,
    redirect,
    url_for,
)

load_dotenv()

app = Flask(__name__)

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

supabase = create_client(url, key)


def user_route(enforce_login=False):
    def decorator(route):
        @functools.wraps(route)
        def route_wrapper(*args, **kwargs):
            jwt = request.cookies.get('auth') or ''
            if enforce_login and not jwt:
                return redirect('/login')
            supabase_user = None
            if jwt:
                try:
                    supabase_user = supabase.auth.get_user(jwt)
                except Exception as e:
                    print(f"Exception: {e}")
            user = supabase_user.user if supabase_user else None
            return route(user, *args, **kwargs)
        return route_wrapper
    return decorator


@app.get("/")
@user_route(enforce_login=False)
def home(supabase_user):
    return render_template('home.html', email=supabase_user.email if supabase_user else '')


@app.get("/protected")
@user_route(enforce_login=True)
def protected(supabase_user):
    return render_template('protected.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = None
        email = request.form.get("email")
        password = request.form.get("password")
        try:
            data = supabase.auth.sign_in_with_password(
                {'email': email, 'password': password})
            response = redirect(url_for('protected'))
            response.set_cookie('auth', data.session.access_token)
            supabase.auth.sign_out()
            return response
        except AuthApiError:
            print("Incorrect email or password")
    return render_template('login.html')


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        try:
            user = supabase.auth.sign_up(
                {"email": email, "password": password})
            return redirect(url_for('login'))
        except AuthApiError:
            print("Incorrect email or password provided.")
    return render_template('signup.html')


@app.route('/logout', methods=["GET", "POST"])
def logout():
    response = redirect(url_for('home'))
    response.delete_cookie('auth')
    supabase.auth.sign_out()
    return response
