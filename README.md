# actix-user-template
Sample of login using Actix-web + Sqlx + Apalis

## Installation
Before you can run the application and use these authentication routes, you need to set up the project environment and dependencies.

To install the required dependencies, follow these steps:

Make sure you have Rust and Docker Compose installed on your system.

Navigate to the project directory.
```bash
cd actix-jwt-with-refresh-token-template
```
Create the .env file.
```bash
cp .local.env .env
```
Start Postgres and Redis.
```bash
docker compose up -d
```
Install Rust dependencies using Cargo:
```bash
cargo build
```
Run the project.
```bash
cargo run
```

## Routes
###  Register User
* Route: /auth/register
* Method: POST
* Description: Allows users to create a new account by providing their registration information, including name, email, and password.
```bash
curl --location 'http://localhost:8000/api/v1/auth/register' \
--header 'Content-Type: application/json' \
--data-raw '{
    "email": "admin@admin.com",
    "name": "Admin",
    "password": "password123",
    "passwordConfirm": "password123",
    "photo": "default.png"
}'
```
###  Login User
* Route: /auth/login
* Method: POST
* Description: Allows users to log in by providing their email and password. Upon successful login, the user receives an access token.
```bash
curl --location 'http://localhost:8000/api/v1/auth/login' \
--header 'Content-Type: application/json' \
--data-raw '{
    "email": "admin@admin.com",
    "password": "batatinha"
}'
```
### Get User Profile
* Route: /auth/me
* Method: GET
* Description: Retrieves the user's profile information. Requires authentication, and the user must be logged in.
```bash
curl --location 'http://localhost:8000/api/v1/auth/me' \
--header 'Cookie: access_token=<ACCESS_TOKEN>'
```
### Logout User
* Route: /auth/logout
* Method: GET
* Description: Logs the user out of the application. Invalidates the current access token, preventing further access to protected resources.
```bash
curl --location 'http://localhost:8000/api/v1/auth/logout'
--header 'Cookie: access_token=<ACCESS_TOKEN>'
```
### Refresh Access Token
* Route: /auth/refresh
* Method: GET
* Description: Refreshes the user's access token, allowing them to maintain their session without re-login.
```bash
curl --location 'http://localhost:8000/api/v1/auth/refresh' \
--header 'Cookie: access_token=<ACCESS_TOKEN>'
```
### Reset Password
* Route: /auth/reset-password/
* Method: POST
* Description: Allows users to reset their password by providing a new password and a password reset token sent via email.
```bash
curl --location 'http://localhost:8000/api/v1/auth/reset-password/' \
--header 'Content-Type: application/json' \
--data '{
    "token": "<RESET_TOKEN>",
    "new_password": "newpass"
}'
```
### Forgot Password
* Route: /auth/forgot-password
* Method: POST
* Description: It initiates the process of resetting a forgotten password by sending a password reset email to the user's registered email address.
```bash
curl --location 'http://localhost:8000/api/v1/auth/forgot-password' \
--header 'Content-Type: application/json' \
--data-raw '{"email": "admin@admin.com"}'
```

