import pytest
from project.app import create_app
from project.models import db


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True

    with app.app_context():
        db.create_all()

    with app.test_client() as client:
        yield client

    with app.app_context():
        db.drop_all()


def test_create_user(client):
    data = {
        'name': 'John Doeaaa',
        'email': 'johndaaoe@example.com',
        'password': 'secretpassword'
    }

    response = client.post('/users', json=data)
    print(response)

    assert response.status_code == 201
