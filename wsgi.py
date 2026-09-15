from torpanel.app import make_app
from torpanel.tunnel_routes import bp as tunnel_blueprint

app = make_app()
app.register_blueprint(tunnel_blueprint)
