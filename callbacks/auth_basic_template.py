from utils import search_user_ldap3

def check_auth(username=None, password=None):

    if not password:
        return False

    if not '@' in username:
        return False

    r = search_user_ldap3(userauth=username, password=password)
    if r:
        return username

    return False
