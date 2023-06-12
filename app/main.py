from flask import Flask
import models
import controllers

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:admin@localhost:5432/dbname'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


if __name__ == '__main__':
    models.db.init_app(app)
    with app.app_context():
        models.db.create_all()

    app.route('/user', methods=['GET'])(controllers.get_all_users)
    app.route('/user/<public_id>', methods=['GET'])(controllers.get_one_user)
    app.route('/user', methods=['POST'])(controllers.create_user)
    app.route('/user/<public_id>', methods=['PUT'])(controllers.promote_user)
    app.route('/user/<public_id>', methods=['DELETE'])(controllers.delete_user)
    app.route('/user', methods=['PUT'])(controllers.update_user)
    app.route('/login', methods=['POST'])(controllers.login)

    app.run(debug=True)