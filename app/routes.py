from controllers import get_all_users, get_one_user, create_user, promote_user, delete_user, update_user, login, \
    get_all_todos, get_one_todo, create_todo, update_todo, delete_todo


def register_routes(app):
    app.route('/users', methods=['GET'])(get_all_users)
    app.route('/users/<id>', methods=['GET'])(get_one_user)
    app.route('/users', methods=['POST'])(create_user)
    app.route('/users/<id>', methods=['PUT'])(promote_user)
    app.route('/users/<id>', methods=['DELETE'])(delete_user)
    app.route('/users', methods=['PUT'])(update_user)
    app.route('/login', methods=['POST'])(login)
    app.route('/todos', methods=['GET'])(get_all_todos)
    app.route('/todos/<todo_id>', methods=['GET'])(get_one_todo)
    app.route('/todos', methods=['POST'])(create_todo)
    app.route('/todos/<todo_id>', methods=['PUT'])(update_todo)
    app.route('/todos/<todo_id>', methods=['DELETE'])(delete_todo)



