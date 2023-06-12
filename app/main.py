from flask import Flask
import models
import routes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:admin@localhost:5432/dbname'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

models.db.init_app(app)
with app.app_context():
    models.db.create_all()

if __name__ == '__main__':
    routes.register_routes(app)
    app.run(debug=True)