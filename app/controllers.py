import jwt
from functools import wraps
from flask import request, jsonify
from models import User
from main import app
from repositories import UserRepository, TodoRepository


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
            current_user = User.query.filter_by(id=data['id']).first()
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
            kwargs['current_user'] = current_user
            return f(*args, **kwargs)
        except jwt.exceptions.DecodeError:
            return jsonify({'message': 'Token is invalid!'}), 401

    return decorated


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    user_repo = UserRepository()
    users = user_repo.get_all_users()

    return jsonify({'users': users})


@app.route('/users/<id>', methods=['GET'])
@token_required
def get_one_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    user_repo = UserRepository()
    user_data = user_repo.get_one_user(id)

    if not user_data:
        return jsonify({'message': 'No user found!'}), 404

    return jsonify({'user': user_data}), 200


@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()

    if not data or 'name' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    user_repo = UserRepository()
    user_repo.create_user(data['name'], data['email'], data['password'])

    return jsonify({'message': 'New user created'}), 201


@app.route('/users/<id>', methods=['PUT'])
@token_required
def promote_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    user_repo = UserRepository()
    user_repo.promote_user(id)

    return jsonify({'message': 'The user has been promoted!'}), 200


@app.route('/users/<id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}), 403

    user_repo = UserRepository()
    user_repo.delete_user(id)

    return jsonify({'message': 'The user has been deleted!'}), 200


@app.route('/users', methods=['PUT'])
@token_required
def update_user(current_user):
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    user_repo = UserRepository()
    user_repo.update_user(current_user.id, data)

    return jsonify({'message': 'User updated successfully'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data['name'] or not data['password']:
        return jsonify({'message': 'Invalid credentials'}), 401

    user_repo = UserRepository()
    token = user_repo.login(data['name'], data['password'])

    return jsonify({'token': token}), 200


@app.route('/todos', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todo_repo = TodoRepository()
    todo = todo_repo.get_all_todos(current_user.id)

    if not todo:
        return jsonify({'message': 'No todos found'}), 404

    return jsonify({'user': todo}), 200


@app.route('/todos/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo_repo = TodoRepository()
    todo = todo_repo.get_one_todo(todo_id, current_user.id)

    if not todo:
        return jsonify({'message': 'No todo found'}), 404

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
    todo_repo = TodoRepository()
    todo_repo.update_todo(todo_id, current_user.id)

    return jsonify({'message': "Todo item has been completed!"}), 200


@app.route('/todos/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo_repo = TodoRepository()
    todo_repo.delete_todo(todo_id, current_user.id)

    return jsonify({'message': "Todo item has been deleted"}), 200
