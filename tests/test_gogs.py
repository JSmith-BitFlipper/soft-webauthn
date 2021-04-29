"""SoftWebauthnDevice usage for (yubico's) fido2 example webserver/application"""

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import pytest
import json

# Hacky way to import `soft_webauthn`
import sys
sys.path.append("..")

from soft_webauthn import SoftWebauthnDevice

cookies = dict()
device = SoftWebauthnDevice()

def findTrim(s, findStr):
    return s.find(findStr) + len(findStr)

def getCookie(setCookie, cookieName):
    idx1 = findTrim(setCookie, cookieName) + 1 # +1 to rid of =
    idx2 = findTrim(setCookie[idx1:], ';') - 1 # -1 to rid of ;
    return setCookie[idx1:idx1+idx2]

def get(url):
    return requests.get('https://localhost:8081' + url,
                        verify=False)

def post(url, data, cookies=dict()):
    return requests.post('https://localhost:8081' + url,
                         files=data,
                         cookies=cookies,
                         verify=False)

def test_gogs_server_login():
    global cookies

    resp = get('/user/login')

    # Set the `i_like_gogs` session cookie
    setCookie = resp.headers['Set-Cookie']
    cookies['i_like_gogs'] = getCookie(setCookie, 'i_like_gogs')

    resp = post('/user/login',
                {"user_name": (None, "durian"),
                 "username": (None, "durian"),
                 "password": (None, "maga2020!"),
                 "assertion": (None, "no-assertion"),
                },
                cookies=cookies,
    )

    if resp.status_code != 200:
        print("Error in login")
        return

    resp = get('/')

    # Set the `csrf` cookie
    setCookie = resp.headers['Set-Cookie']
    cookies['_csrf'] = getCookie(setCookie, '_csrf')

    print("Successfully logged in user!")

def test_gogs_server_registration():  # pylint: disable=redefined-outer-name
    """Registration example"""
    global cookies
    global device

    # Begin registration
    resp = post('/webauthn/begin_register',
                {"username": (None, "durian")},
                cookies=cookies
    )

    if resp.status_code != 200:
        print("Error in begin_register")
        return

    # Set the `webauthn-session` cookie
    setCookie = resp.headers['Set-Cookie']
    cookies['webauthn-session'] = getCookie(setCookie, 'webauthn-session')

    options = {'publicKey': resp.json()}

    # User holds an authenticator.
    #
    # NOTE: SoftWebauthnDevice emulates mixed client and authenticator behavior
    # and can be used for testing Webauthn/FIDO2 enabled applications during
    # continuous integration test-cases.
    attestation = device.create(options, 'https://localhost:8081')

    resp = post('/webauthn/finish_register',
                {"username": (None, "durian"),
                 "credentials": (None, json.dumps(attestation)),
                },
                cookies=cookies,
    )

    if resp.status_code == 200:
        print("Successfully registered webauthn user!")
    else:
        print("Error in register webauthn user")

def test_gogs_server_change_email():
    global cookies

    auth_text = "Confirm profile details: username durian email test@email.comsada"

    resp = post('/webauthn/begin_attestation',
                {"auth_text": (None, auth_text)},
                cookies=cookies
    )

    if resp.status_code != 200:
        print("Error in begin_attestation")
        return

    # Set the `webauthn-session` cookie
    setCookie = resp.headers['Set-Cookie']
    cookies['webauthn-session'] = getCookie(setCookie, 'webauthn-session')

    options = {'publicKey': resp.json()}

    #  User holds an authenticator
    attestation = device.get(options, 'https://localhost:8081')

    resp = post('/user/settings',
                {"_csrf": (None, cookies['_csrf']),
                 "name": (None, "durian"),
                 "full_name": (None, ""),
                 "email": (None, "test@email.comsada"),
                 "website": (None, ""),
                 "location": (None, ""),
                 "auth_text": (None, auth_text),
                 "assertion": (None, json.dumps(attestation)),
                },
                cookies=cookies,
    )

    if resp.status_code == 200:
        print("Successfully changed user email!")
    else:
        print("Error in change user email")

if __name__ == '__main__':
    test_gogs_server_login()
    test_gogs_server_registration()
    test_gogs_server_change_email()

