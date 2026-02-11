from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
# from flask_seeder import FlaskSeeder
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow

# from app.error import ratelimit_handler


class Base(MappedAsDataclass, DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
ma = Marshmallow()
migrate = Migrate()
# seeder = FlaskSeeder()
bcrypt = Bcrypt()
# limiter = Limiter(get_remote_address, on_breach=ratelimit_handler)
jwt = JWTManager()

