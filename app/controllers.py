import datetime
import uuid
import jwt
from functools import wraps
from flask import request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, Todo
from main import app
from repositories import UserRepository, TodoRepository
from utils.validation_helpers import is_valid_email


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'error': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['id']).first()
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
            kwargs['current_user'] = current_user
            return f(*args, **kwargs)
        except jwt.exceptions.DecodeError:
            return jsonify({'error': 'Token is invalid!'}), 401

    return decorated


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'error': 'Cannot perform that function!'}), 403

    user_repo = UserRepository()
    users = user_repo.get_all_users()

    return jsonify({'users': users})


@app.route('/users/<id>', methods=['GET'])
@token_required
def get_one_user(current_user, id):
    if not current_user.admin:
        return jsonify({'error': 'Cannot perform that function!'}), 403

    user_repo = UserRepository()
    user_data = user_repo.get_one_user(id)

    if not user_data:
        return jsonify({'error': 'No user found!'}), 404

    return jsonify({'user': user_data}), 200


@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()

    if not data or 'name' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = User.query.filter_by(name=data['name']).first()
    if existing_user:
        return jsonify({'error': 'User with that name already exists'}), 409

    if not is_valid_email(data['email']):
        return jsonify({'error': 'Invalid email address'}), 400

    user_repo = UserRepository()
    user_repo.create_user(data['name'], data['email'], data['password'])

    return jsonify({'message': 'New user created'}), 201


@app.route('/users/<id>', methods=['PUT'])
@token_required
def promote_user(current_user, id):
    if not current_user.admin:
        return jsonify({'error': 'Cannot perform that function!'}), 403

    try:
        uuid.UUID(id)
    except ValueError:
        return jsonify({'error': 'Invalid user ID'}), 400

    user = User.query.filter_by(id=id).first()
    if not user:
        return jsonify({'error': 'No user found!'})

    user_repo = UserRepository()
    user_repo.promote_user(user)

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/users/<id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    if not current_user.admin:
        return jsonify({'error': 'Cannot perform that function!'}), 403

    try:
        uuid.UUID(id)
    except ValueError:
        return jsonify({'error': 'Invalid user ID'}), 400

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'error': 'No user found!'})

    if user.admin:
        return jsonify({'error': "You can't delete admin!"})

    user_repo = UserRepository()
    user_repo.delete_user(user)

    return jsonify({'message': 'The user has been deleted!'}), 200


@app.route('/users', methods=['PUT'])
@token_required
def update_user(current_user):
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if 'name' not in data and 'email' not in data and 'password' not in data:
        return jsonify({'error': 'Bad request'}), 400

    user = User.query.filter_by(id=current_user.id).first()

    if not user:
        return jsonify({'error': 'User not found'}), 400
    existing_user = User.query.filter(User.name == data['name'], User.id != user.id).first()
    if existing_user:
        return jsonify({'error': 'User with that name already exists'}), 400

    if not is_valid_email(data['email']):
        return jsonify({'error': 'Invalid email address'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    user_repo = UserRepository()
    user_repo.update_user(user, data, hashed_password)

    return jsonify({'message': 'User updated successfully'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data['name'] or not data['password']:
        return jsonify({'error': 'Invalid credentials'}), 401

    user = User.query.filter_by(name=data['name']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode(
        {'id': str(user.id), 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
        app.config['SECRET_KEY'],
        algorithm='HS256')

    return jsonify({'token': token}), 200


@app.route('/todos', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todo_repo = TodoRepository()
    todo = todo_repo.get_all_todos(current_user.id)

    if not todo:
        return jsonify({'error': 'No todos found'}), 404

    return jsonify({'user': todo}), 200


@app.route('/todos/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo_repo = TodoRepository()
    todo = todo_repo.get_one_todo(todo_id, current_user.id)

    if not todo:
        return jsonify({'error': 'No todo found'}), 404

    return jsonify({'todo': todo}), 200


@app.route('/todos', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    if not data or 'text' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    todo_repo = TodoRepository()
    todo_repo.create_todo(data['text'], current_user.id)

    return jsonify({'message': 'Todo created!'}), 201


@app.route('/todos/<todo_id>', methods=['PUT'])
@token_required
def update_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'error': 'Todo not found'}), 404

    todo_repo = TodoRepository()
    todo_repo.update_todo(todo)

    return jsonify({'message': 'Todo completed successfully'}), 200


@app.route('/todos/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'error': 'Todo not found'}), 404

    todo_repo = TodoRepository()
    todo_repo.delete_todo(todo)

    return jsonify({'message': "Todo item has been deleted"}), 200
