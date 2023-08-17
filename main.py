from fastapi import FastAPI
from models import User

app = FastAPI()


db = [
    User(
        id=1,
        first_name="mohammadreza",
        last_name='rouhani',
        username='mrceo',
        email='mohammad@email.com',
        password='12345678'
    ),
]


@app.get('/')
def root():
    return {'hello': 'world'}


@app.get('/api/users/')
def get_users():
    return db
