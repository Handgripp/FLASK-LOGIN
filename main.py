import uuid
import jwt
import datetime
import re
from functools import wraps
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:admin@localhost:5432/dbname'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), unique=True, nullable=False)
    name = db.Column(db.String(50))
    email = db.Column(db.String(120))
    password = db.Column(db.String(128))
    admin = db.Column(db.Boolean)


with app.app_context():
    db.create_all()


def is_valid_email(email):
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(email_pattern, email) is not None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except jwt.exceptions.DecodeError:
            return jsonify({'message': 'Token is invalid!'}), 401

        if 'token' not in session or session['token'] != token:
            return jsonify({'message': 'Token is no longer valid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = str(user.public_id)
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = str(user.public_id)
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    if not data or 'name' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = User.query.filter_by(name=data['name']).first()
    if existing_user:
        return jsonify({'error': 'User with that name already exists'}), 409

    if not is_valid_email(data['email']):
        return jsonify({'error': 'Invalid email address'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], email=data['email'], password=hashed_password,
                    admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    if user.admin:
        return jsonify({'message': "You can't delete admin!"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/user', methods=['PUT'])
@token_required
def update_user(current_user):
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    user = User.query.filter_by(public_id=current_user.public_id).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if 'name' in data:
        existing_user = User.query.filter(User.name == data['name'], User.public_id != user.public_id).first()
        if existing_user:
            return jsonify({'error': 'User with that name already exists'}), 409
        user.name = data['name']

    if 'email' in data:
        user.email = data['email']
        if not is_valid_email(data['email']):
            return jsonify({'error': 'Invalid email address'}), 400

    if 'password' in data:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        user.password = hashed_password

    if data['name'] == user.name and data['email'] == user.email:
        return jsonify({'message': 'No changes made'}), 400

    db.session.commit()

    return jsonify({'message': 'User updated successfully'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data['name'] or not data['password']:
        return jsonify({'message': 'Invalid credentials'}), 401

    user = User.query.filter_by(name=data['name']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode(
        {'public_id': str(user.public_id), 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
        app.config['SECRET_KEY'],
        algorithm='HS256')

    session['token'] = token

    return jsonify({'token': token})


@app.route('/logout', methods=['POST'])
@token_required
def logout():
    session.pop('token', None)
    return jsonify({'message': 'Logged out successfully'})


if __name__ == '__main__':
    app.run(debug=True)
