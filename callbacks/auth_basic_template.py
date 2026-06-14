from utils import search_user

def check_auth(username=None, password=None):

    if not password:
        return False

    r = search_user(userauth=username, password=password)
    if r:
        return username

    return False