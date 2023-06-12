from controllers import get_all_users, get_one_user, create_user, promote_user, delete_user, update_user, login


def register_routes(app):
    app.route('/user', methods=['GET'])(get_all_users)
    app.route('/user/<public_id>', methods=['GET'])(get_one_user)
    app.route('/user', methods=['POST'])(create_user)
    app.route('/user/<public_id>', methods=['PUT'])(promote_user)
    app.route('/user/<public_id>', methods=['DELETE'])(delete_user)
    app.route('/user', methods=['PUT'])(update_user)
    app.route('/login', methods=['POST'])(login)



