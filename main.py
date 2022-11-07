# set up flask
import hashlib
import os
from datetime import timedelta
from flask import Flask, render_template, url_for, redirect, g, session, Response, jsonify, request, make_response
from flask_login import UserMixin
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import warnings

from sqlalchemy import func
from flask_httpauth import HTTPBasicAuth

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from flask_marshmallow import Marshmallow

from flask_swagger_ui import get_swaggerui_blueprint
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
import datetime

app = Flask("__name__")
auth = HTTPBasicAuth()

flag = True

app.config[
    "SQLALCHEMY_DATABASE_URI"] = "snowflake://Razak:Welcome13!@citixfd-xvb70636/API_Control_DB/API_Schema?warehouse=API_WH"
db = SQLAlchemy(app)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

# swagger specific
SWAGGER_URL = '/homeAPI'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "EmeraldX APIs"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

ma = Marshmallow(app)

# set a connection manager for security
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create a user Class
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(300), nullable=False)


# Create the class questions
class Questions(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(200), nullable=True)
    link = db.Column(db.String(2000), nullable=True)
    score = db.Column(db.Float(), nullable=True)


# create db schema class
class QuestionSchema(ma.Schema):
    class Meta:
        fields = ('id', 'title', 'link', 'score')


# instantiate schema objects for todolist and todolists
Question_schema = QuestionSchema(many=False)
Questions_schema = QuestionSchema(many=True)


# Create a login form Class to interect with the login.html webpage
class LoginFrom(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": ""})  #
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": ""})  #
    submit = SubmitField("Login")

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        encoded_str = password.encode()
        hash_obj_sha256 = hashlib.sha256(encoded_str).hexdigest()
        if user.password == hash_obj_sha256:
            return username


@app.route('/expired')
def expired():
    session.clear()
    return Response('<p>session expired</p>')


# define a root , and define a function when someone get into the route.@app.route("/")
@app.route("/")
def index():
    return redirect(url_for("login"))


# define a route to the home page
#@app.route("/homeAPI", methods=["GET", "POST"])
#@login_required
#def home():
#    return render_template("home.html")


# define a route to the login page
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginFrom()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            encoded_str = form.password.data.encode()
            hash_obj_sha256 = hashlib.sha256(encoded_str).hexdigest()
            if user.password == hash_obj_sha256:
                login_user(user)
                return redirect(url_for("swagger_ui.show"))
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))


# here is to make sure that if the user is not active for 230 then log him out
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=20)
    session.modified = True
    g.user = current_user


# handle misunderstood
@app.errorhandler(400)
def hand400error(error):
    return Response('<p>misunderstood</p>')


# handle login failed
@app.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')


# get all questions
@app.route("/Test-request", methods=["GET"])
@login_required
def get_questions():
    questions = Questions.query.all()
    result_set = Questions_schema.dump(questions)
    return jsonify(result_set)


# get all questions from an App
@app.route("/request", methods=["GET"])
@auth.login_required
def get_questions_app():
    questions = Questions.query.all()
    result_set = Questions_schema.dump(questions)
    return jsonify(result_set)


# get a specific question
@app.route("/Test-request/<int:id>", methods=["GET"])
@login_required
# @auth.login_required
def get_question(id):
    question = Questions.query.get_or_404(int(id))
    return Question_schema.jsonify(question)


# get a specific question from an App
@app.route("/request/<int:id>", methods=["GET"])
@auth.login_required
def get_question_app(id):
    question = Questions.query.get_or_404(int(id))
    return Question_schema.jsonify(question)


# get incremental from a certain ID:
@app.route("/Test-request-incremental/<int:ide>", methods=["GET"])
@login_required
def get_question_incremental(ide):
    questions = db.session.query(Questions).filter(Questions.id >= ide)
    result_set = Questions_schema.dump(questions)
    return jsonify(result_set)

# get incremental from a certain from an App:
@app.route("/request-incremental/<int:ide>", methods=["GET"])
@auth.login_required
def get_question_incremental_app(ide):
    questions = db.session.query(Questions).filter(Questions.id >= ide)
    result_set = Questions_schema.dump(questions)
    return jsonify(result_set)



# add a question
@app.route("/Test-request", methods=["POST"])
@login_required
def add_question():
    try:
        max_id = db.session.query(func.max(Questions.id)).one()
        id = max_id[0] + 1
        title = request.json['title']
        link = request.json['link']
        score = request.json['score']

        new_question = Questions(id=id, title=title, link=link, score=score)

        db.session.add(new_question)
        db.session.commit()

        return Question_schema.jsonify(new_question)
    except Exception as e:
        return jsonify({"Error": ": Invalid Request, please try again."})


# add a question from an app
@app.route("/request", methods=["POST"])
@auth.login_required
def add_question_app():
    try:
        max_id = db.session.query(func.max(Questions.id)).one()
        id = max_id[0] + 1
        title = request.json['title']
        link = request.json['link']
        score = request.json['score']

        new_question = Questions(id=id, title=title, link=link, score=score)

        db.session.add(new_question)
        db.session.commit()

        return Question_schema.jsonify(new_question)
    except Exception as e:
        return jsonify({"Error": ": Invalid Request, please try again."})


# update a question
@app.route("/Test-request/<int:id>", methods=["PUT"])
@login_required
def update_question(id):
    question = Questions.query.get_or_404(int(id))

    try:
        title = request.json['title']
        link = request.json['link']
        score = request.json['score']

        question.title = title
        question.link = link
        question.score = score

        db.session.commit()
    except Exception as e:
        return jsonify({"Error": "Invalid request, please try again."})

    return Question_schema.jsonify(question)


# update a question from an app
@app.route("/request/<int:id>", methods=["PUT"])
@auth.login_required
def update_question_app(id):
    question = Questions.query.get_or_404(int(id))

    try:
        title = request.json['title']
        link = request.json['link']
        score = request.json['score']

        question.title = title
        question.link = link
        question.score = score

        db.session.commit()
    except Exception as e:
        return jsonify({"Error": "Invalid request, please try again."})

    return Question_schema.jsonify(question)


# delete a question
@app.route("/Test-request/<int:id>", methods=["DELETE"])
@login_required
def delete_question(id):
    question = Questions.query.get_or_404(int(id))
    db.session.delete(question)
    db.session.commit()
    return jsonify({"Success": "question deleted."})


# delete a question from an App
@app.route("/request/<int:id>", methods=["DELETE"])
@auth.login_required
def delete_question_app(id):
    question = Questions.query.get_or_404(int(id))
    db.session.delete(question)
    db.session.commit()
    return jsonify({"Success": "question deleted."})


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)
