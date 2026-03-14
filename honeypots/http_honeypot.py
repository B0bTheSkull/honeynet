"""HTTP honeypot using Flask — fake admin panel."""
from flask import Flask, request, render_template_string, jsonify


FAKE_LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Admin Panel — Login</title>
<style>
  body { font-family: Arial, sans-serif; background: #1a1a2e; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .login-box { background: #16213e; padding: 2rem; border-radius: 8px; border: 1px solid #0f3460; width: 320px; }
  h2 { color: #e94560; text-align: center; margin-bottom: 1.5rem; }
  input { width: 100%; padding: 0.6rem; margin: 0.5rem 0; background: #0f3460; border: 1px solid #e94560; color: #fff; border-radius: 4px; box-sizing: border-box; }
  button { width: 100%; padding: 0.75rem; background: #e94560; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; margin-top: 1rem; }
  .error { color: #ff6b6b; font-size: 0.85rem; text-align: center; margin-top: 0.5rem; }
  .logo { text-align: center; color: #e94560; font-size: 0.8rem; margin-top: 1rem; }
</style>
</head>
<body>
<div class="login-box">
  <h2>🔒 Admin Panel</h2>
  <form method="POST">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <div class="logo">v2.4.1 — Internal Use Only</div>
</div>
</body>
</html>
"""


def create_app(logger):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "honeynet-fake-key"

    def get_real_ip():
        return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    @app.route("/", methods=["GET"])
    @app.route("/admin", methods=["GET"])
    @app.route("/login", methods=["GET"])
    @app.route("/wp-admin", methods=["GET"])
    @app.route("/phpmyadmin", methods=["GET"])
    def login_page():
        ip = get_real_ip()
        path = request.path
        logger.log("HTTP", ip, request.environ.get("REMOTE_PORT", 0), "page_probe",
                   {"path": path, "user_agent": request.user_agent.string})
        return render_template_string(FAKE_LOGIN_PAGE, error=None)

    @app.route("/", methods=["POST"])
    @app.route("/admin", methods=["POST"])
    @app.route("/login", methods=["POST"])
    @app.route("/wp-admin", methods=["POST"])
    def login_attempt():
        ip = get_real_ip()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        logger.log("HTTP", ip, request.environ.get("REMOTE_PORT", 0), "login_attempt",
                   {"username": username, "password": password, "path": request.path,
                    "user_agent": request.user_agent.string})
        return render_template_string(FAKE_LOGIN_PAGE, error="Invalid credentials. Please try again.")

    @app.route("/.env")
    @app.route("/.git/HEAD")
    @app.route("/wp-config.php")
    @app.route("/config.php")
    @app.route("/phpinfo.php")
    @app.route("/backup.zip")
    @app.route("/server-status")
    @app.route("/api/v1/users")
    @app.route("/api/v1/admin")
    def sensitive_probe():
        ip = get_real_ip()
        path = request.path
        logger.log("HTTP", ip, request.environ.get("REMOTE_PORT", 0), "sensitive_file_probe",
                   {"path": path, "user_agent": request.user_agent.string})
        # Return fake-looking responses
        fake_responses = {
            "/.env": ("DB_HOST=localhost\nDB_USER=admin\nDB_PASS=REDACTED\nSECRET_KEY=REDACTED\n", "text/plain"),
            "/.git/HEAD": ("ref: refs/heads/main\n", "text/plain"),
            "/phpinfo.php": ("<html><body>PHP Version 7.4.3 — Info suppressed</body></html>", "text/html"),
            "/server-status": ("<html><body>Apache Server Status — access restricted</body></html>", "text/html"),
        }
        if path in fake_responses:
            content, ctype = fake_responses[path]
            return content, 200, {"Content-Type": ctype}
        return "", 404

    @app.errorhandler(404)
    def not_found(e):
        ip = get_real_ip()
        path = request.path
        logger.log("HTTP", ip, request.environ.get("REMOTE_PORT", 0), "404_probe",
                   {"path": path, "user_agent": request.user_agent.string})
        return "", 404

    return app


class HTTPHoneypot:
    def __init__(self, port, logger):
        self.port = port
        self.logger = logger
        self.app = create_app(logger)

    def start(self):
        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)
        self.app.run(host="0.0.0.0", port=self.port, debug=False, use_reloader=False)
