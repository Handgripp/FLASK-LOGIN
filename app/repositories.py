import uuid
from werkzeug.security import generate_password_hash
from models import User, Todo, db


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
        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(id=str(uuid.uuid4()), name=name, email=email, password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()

    @staticmethod
    def promote_user(user):
        user.admin = True
        db.session.commit()

    @staticmethod
    def delete_user(user):
        db.session.delete(user)
        db.session.commit()

    @staticmethod
    def update_user(user, data, hashed_password):
        user.name = data['name']
        user.email = data['email']
        user.password = hashed_password
        db.session.commit()


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

        return {
            'id': todo.id,
            'text': todo.text,
            'is_completed': todo.is_completed
        }

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
    def update_todo(todo):
        todo.is_completed = True
        db.session.commit()

    @staticmethod
    def delete_todo(todo):
        db.session.delete(todo)
        db.session.commit()
