from utils import search_user

def check_auth(username=None,password=None):

    #if auth ok return username
    #return username

    r = search_user(userauth=username,password=password)
    if r:
        return r[1]['sAMAccountName'][0].decode('utf-8')
    
    #if auth fail return False
    return False
