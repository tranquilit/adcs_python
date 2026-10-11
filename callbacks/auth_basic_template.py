from utils import search_user_ldap3, get_default_realm

def check_auth(username=None, password=None):

    if not username or not password:
        return False

    username = username.strip()
    realm = get_default_realm().upper()

    if "@" in username:
        user, domain = username.split("@", 1)

        if not user or domain.upper() != realm:
            return False
    else:
        user = username

    username = f"{user}@{realm}"

    r = search_user_ldap3(userauth=username, password=password)

    return username if r else False
