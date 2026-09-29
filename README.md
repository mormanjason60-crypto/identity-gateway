# Zero-Trust Identity Gateway & RBAC API

## Overview
A microservice identity gateway built with Python, Flask, and JSON Web Tokens (JWT). It implements a Zero-Trust architecture model where requests are continuously verified against cryptographically signed tokens to enforce Role-Based Access Control (RBAC).

## Features
* **Stateless Token Authentication:** Issues 15-minute expiration JWTs signed with `HS256`.
* **RBAC Middleware Decorator:** Intercepts incoming route requests to decode token signatures and restrict resource access based on assigned user roles (`admin`, `user`, `guest`).
* **Error Handling:** Returns explicit HTTP status codes (`401 Unauthorized`, `403 Forbidden`) for expired tokens, invalid signatures, or missing auth headers.

## API Endpoints
* `POST /api/v1/auth/login`: Accepts JSON body `{"username": "string", "role": "string"}` and returns a signed JWT.
* `GET /api/v1/resource/admin`: Protected route requiring a valid `Bearer <token>` with `admin` role scope.

## How to Run
```bash
python3 -m venv venv
source venv/bin/activate
pip install flask pyjwt
python3 app.py
