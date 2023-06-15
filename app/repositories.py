import datetime
import uuid
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from main import app
from models import User, Todo, db
from flask import jsonify
from utils.validation_helpers import is_valid_email


class UserRepository:
    @staticmethod
    def get_all_users():
        users = User.query.all()

        output = []

        for user in users:
            user_data = {}
            user_data['id'] = str(user.id)
            user_data['name'] = user.name
            user_data['email'] = user.email
            user_data['password'] = user.password
            user_data['admin'] = user.admin
            output.append(user_data)

        return output

    @staticmethod
    def get_one_user(user_id):
        user = User.query.filter_by(id=user_id).first()

        user_data = {
            'id': str(user.id),
            'name': user.name,
            'email': user.email,
            'password': user.password,
            'admin': user.admin
        }

        return user_data

    @staticmethod
    def create_user(name, email, password):
        existing_user = User.query.filter_by(name=name).first()
        if existing_user:
            return jsonify({'error': 'User with that name already exists'}), 409

        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email address'}), 400

        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(id=str(uuid.uuid4()), name=name, email=email, password=hashed_password,
                        admin=False)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'New user created'})

    @staticmethod
    def promote_user(user_id):
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({'message': 'No user found!'})

        user.admin = True
        db.session.commit()

        return jsonify({'message': 'The user has been promoted!'})

    @staticmethod
    def delete_user(user_id):
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({'message': 'No user found!'})

        if user.admin:
            return jsonify({'message': "You can't delete admin!"})

        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'The user has been deleted!'})

    @staticmethod
    def update_user(user_id, data):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if 'name' in data:
            existing_user = User.query.filter(User.name == data['name'], User.id != user.id).first()
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

        db.session.commit()

        return jsonify({'message': 'User updated successfully'})

    @staticmethod
    def login(name, password):
        user = User.query.filter_by(name=name).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid credentials'}), 401

        token = jwt.encode(
            {'id': str(user.id), 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
            app.config['SECRET_KEY'],
            algorithm='HS256')

        return jsonify({'token': token})


class TodoRepository:
    @staticmethod
    def get_all_todos(user_id):
        todos = Todo.query.filter_by(user_id=user_id).all()

        output = []

        for todo in todos:
            todo_data = {}
            todo_data['id'] = todo.id
            todo_data['text'] = todo.text
            todo_data['is_completed'] = todo.is_completed
            output.append(todo_data)

        return output

    @staticmethod
    def get_one_todo(todo_id, user_id):
        todo = Todo.query.filter_by(id=todo_id, user_id=user_id).first()

        if not todo:
            return None

        todo_data = {
            'id': todo.id,
            'text': todo.text,
            'is_completed': todo.is_completed
        }

        return todo_data

    @staticmethod
    def create_todo(text, user_id):
        new_todo = Todo(
            text=text,
            is_completed=False,
            user_id=user_id
        )
        db.session.add(new_todo)
        db.session.commit()

        return {
            'id': new_todo.id,
            'text': new_todo.text,
            'is_completed': new_todo.is_completed
        }

    @staticmethod
    def update_todo(todo_id, user_id):
        todo = Todo.query.filter_by(id=todo_id, user_id=user_id).first()

        if not todo:
            return jsonify({'message': "No todo found"})

        todo.is_completed = True
        db.session.commit()

        return jsonify({'message': "Todo item has been completed!"})

    @staticmethod
    def delete_todo(todo_id, user_id):
        todo = Todo.query.filter_by(id=todo_id, user_id=user_id).first()

        if not todo:
            return jsonify({'message': "No todo found"})

        db.session.delete(todo)
        db.session.commit()

        return jsonify({'message': "Todo item has been deleted"})
