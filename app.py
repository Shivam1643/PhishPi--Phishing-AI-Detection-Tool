# from flask import Flask, request, render_template
# import joblib

# app = Flask(__name__)

# # Load the model
# phish_model = joblib.load('phishing.pkl')

# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/predict', methods=['POST'])
# def predict():
#     url = request.form['url']
#     X_predict = [url]
#     y_predict = phish_model.predict(X_predict)

#     if y_predict[0] == 'bad':
#         result = "This is a Phishing Site"
#     else:
#         result = "This is not a Phishing Site"

#     return render_template('result.html', url=url, result=result)

# if __name__ == '__main__':
#     app.run(host="127.0.0.1", port=8000, debug=True)


from flask import Flask, request, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
import joblib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure secret key
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load the model
phish_model = joblib.load('phishing.pkl')

# Replace this with your User model or database logic
class User(UserMixin):
    def __init__(self, user_id, username, password):
        self.id = user_id
        self.username = username
        self.password = password  # In a real app, use secure password hashing

# Replace this with your actual user database or logic
users = {
    '1': User('1', 'user1', 'password1'),
    '2': User('2', 'user2', 'password2'),
}

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        user = next((user for user in users.values() if user.username == username), None)
        if user and form.password.data == user.password:  # Replace with secure password checking
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index')) 
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    url = request.form['url']
    X_predict = [url]
    y_predict = phish_model.predict(X_predict)

    if y_predict[0] == 'bad':
        result = "This is a Phishing Site"
    else:
        result = "This is not a Phishing Site"

    return render_template('result.html', url=url, result=result)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Replace this with your actual user registration logic
        user_id = str(len(users) + 1)
        new_user = User(user_id, form.username.data, form.password.data)
        users[user_id] = new_user
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8000, debug=True)
