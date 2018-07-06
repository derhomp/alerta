
import ldap
import os

from flask import current_app, request, jsonify
from flask_cors import cross_origin

from alerta.auth.utils import create_token, get_customers
from alerta.exceptions import ApiError
from alerta.models.user import User
from . import auth

# Define variables
ldapurl = os.environ.get('LDAP_URL') or current_app.config["LDAP_URL"]
binddn = os.environ.get('LDAP_BINDDN') or current_app.config["LDAP_BINDDN"]
binddnpw = os.environ.get('LDAP_BINDDN_PW') or current_app.config["LDAP_BINDDN_PW"]
ldapbasedn = os.environ.get('LDAP_BASEDN') or current_app.config["LDAP_BASEDN"]
ldaprole = os.environ.get('LDAP_ROLE') or current_app.config["LDAP_ROLE"] or 'user'


@auth.route('/auth/login', methods=['OPTIONS', 'POST'])
@cross_origin(supports_credentials=True)
def login():
    # Retrieve required fields from client request
    try:
        email = request.json.get('username', None) or request.json['email']
        password = request.json['password']
    except KeyError:
        raise ApiError("must supply 'username' and 'password'", 401)

    # Define ldap filter use %s for username
    ldapfilter = f'(mail={email})'

    # Attempt LDAP AUTH with binddn
    try:
        ldap_connection = ldap.initialize(ldapurl)
        ldap_connection.simple_bind_s(binddn, binddnpw)
    except ldap.INVALID_CREDENTIALS:
        raise ApiError("invalid username or password for binddn", 401)
    except Exception as e:
        raise ApiError(str(e), 500)

    # Start LDAP search
    try:
        ldapquery = ldap_connection.search_s(ldapbasedn, ldap.SCOPE_SUBTREE, ldapfilter, ['cn'])
        userdn = ldapquery[0][0]
        usercn = str(b''.join(ldapquery[0][1]['cn']), 'utf-8')

    except Exception:
        raise ApiError("invalid username or basedn", 401)

    # Attempt LDAP AUTH
    try:
        ldap_connection.simple_bind_s(userdn, password)
    except ldap.INVALID_CREDENTIALS:
        raise ApiError("invalid password", 401)
    except Exception as e:
        raise ApiError(str(e), 500)

    # Create user if not yet there
    user = User.find_by_email(email=email)
    if not user:
        user = User(usercn, email, "", ldaprole.split(), "LDAP user", email_verified=True)
        user.create()

    # Check user is active
    if user.status != 'active':
        raise ApiError('user not active', 403)

    # Assign customers & update last login time
    customers = get_customers(user.email, groups=[user.domain])
    user.update_last_login()

    # Generate token
    token = create_token(user.id, user.name, user.email, provider='basic_ldap', customers=customers,
                         roles=user.roles, email=user.email, email_verified=user.email_verified)
    return jsonify(token=token.tokenize)

