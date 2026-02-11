from flask import Flask
from config import config
from app.extensions import (
    db,
    migrate,
    bcrypt,
    # limiter,
    jwt,
    ma,
)

def create_app(config_class=None):
    """Application factory pattern"""
    # create and configure the app
    app = Flask(__name__)

    # load configuration
    if config_class is None:
        import os
        env = os.getenv("FLASK_ENV", "development")
        config_class = config.get(env)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)
    ma.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    # limiter.init_app(app)
    jwt.init_app(app)

    # Import models module to register all models
    from app.database import model

    # Register blueprints here
    # app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    # app.register_blueprint(user_bp, url_prefix="/api/v1/user")

    return app
