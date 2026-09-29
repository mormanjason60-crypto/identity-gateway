from datetime import datetime, timedelta, timezone
import functools
from flask import Flask, jsonify, request
import jwt

app = Flask(__name__)

# Secret key used to cryptographically sign tokens
SECRET_KEY = "meta_zero_trust_internal_key_demo"


def token_required(allowed_roles=None):
    """Decorator to enforce JWT validation and role-based access control."""

    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            token = None
            auth_header = request.headers.get("Authorization")

            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

            if not token:
                return (
                    jsonify(
                        {
                            "status": "denied",
                            "message": "Missing Bearer token.",
                        }
                    ),
                    401,
                )

            try:
                # Cryptographically verify and decode the token
                payload = jwt.decode(
                    token, SECRET_KEY, algorithms=["HS256"]
                )
                request_role = payload.get("role")

                if (
                    allowed_roles
                    and request_role.lower() not in allowed_roles
                ):
                    return (
                        jsonify(
                            {
                                "status": "forbidden",
                                "message": (
                                    "Access denied: insufficient permissions."
                                ),
                            }
                        ),
                        403,
                    )

            except jwt.ExpiredSignatureError:
                return (
                    jsonify(
                        {
                            "status": "denied",
                            "message": "Token has expired.",
                        }
                    ),
                    401,
                )
            except jwt.InvalidTokenError:
                return (
                    jsonify(
                        {
                            "status": "denied",
                            "message": "Invalid token signature.",
                        }
                    ),
                    401,
                )

            return f(*args, **kwargs)

        return decorated

    return decorator


@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    """Generates a signed JWT upon valid user login."""
    data = request.get_json() or {}
    username = data.get("username")
    role = data.get("role", "guest")

    if not username:
        return jsonify({"message": "Username is required"}), 400

    payload = {
        "user": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify(
        {"status": "authenticated", "token": token, "expires_in": "15m"}
    )


@app.route("/api/v1/resource/admin", methods=["GET"])
@token_required(allowed_roles=["admin"])
def protected_admin_resource():
    """Restricted endpoint accessible only by 'admin' role."""
    return jsonify(
        {
            "status": "success",
            "data": "Sensitive system infrastructure operational.",
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

