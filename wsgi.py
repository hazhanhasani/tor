import torpanel.app as app_module
from torpanel.password_reset import effective_admin_password_hash, register_password_recovery

bootstrap_hash = effective_admin_password_hash()
if bootstrap_hash:
    app_module.ADMIN_PASSWORD_HASH = bootstrap_hash

app = app_module.make_app()
register_password_recovery(app)
