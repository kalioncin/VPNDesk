"""Store secrets in the OS credential vault when available; never write them to settings.json."""
SERVICE='VPNDesk'
USERNAME='github_token'

def get_token():
    try:
        import keyring
        return keyring.get_password(SERVICE,USERNAME) or ''
    except Exception:
        return ''

def set_token(value):
    try:
        import keyring
        if value:
            keyring.set_password(SERVICE,USERNAME,value)
        else:
            try: keyring.delete_password(SERVICE,USERNAME)
            except Exception: pass
        return True
    except Exception:
        return False
