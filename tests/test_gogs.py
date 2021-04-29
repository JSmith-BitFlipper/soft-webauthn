"""SoftWebauthnDevice usage for (yubico's) fido2 example webserver/application"""

# Disable the HTTPs verify warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import pytest
import json
import pickle

from multiprocessing import Process, Queue
import time
import os

import numpy as np

# Hacky way to import `soft_webauthn`
import sys
sys.path.append("..")

from soft_webauthn import SoftWebauthnDevice

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

class User():
    def __init__(self, username, password):
        self.cookies = dict()
        
        # Remember the input arguments
        self.username = username
        self.password = password

        # Generate a new device for this `User`
        self.device = SoftWebauthnDevice()
        
        # Log the user in and webauthn register them (if necessary)
        self.log_in_and_register()

    def log_in_and_register(self):
        self.gogs_server_login()

        # Register only if the user does not have webauthn enabled
        if not self.is_webauthn_enabled():
            self.gogs_server_registration()

    def is_webauthn_enabled(self):
        resp = get('/webauthn/is_enabled/{}'.format(self.username))

        if resp.status_code != 200:
            print("Error with webauthn is enabled")
            return False

        return resp.json()['webauthn_is_enabled']

    def gogs_server_login(self):
        # Get the `i_like_gogs` session cookie
        resp = get('/user/login')

        # Set the `i_like_gogs` session cookie
        setCookie = resp.headers['Set-Cookie']
        self.cookies['i_like_gogs'] = getCookie(setCookie, 'i_like_gogs')

        attestation = "no-assertion"

        # If webauthn is enabled, generate an `assertion` object
        if self.is_webauthn_enabled():
            resp = post('/webauthn/begin_login',
                        {"username": (None, self.username)},
                        cookies=self.cookies,
            )

            if resp.status_code != 200:
                print("Error in begin_login")
                return

            # Set the `webauthn-session` cookie
            setCookie = resp.headers['Set-Cookie']
            self.cookies['webauthn-session'] = getCookie(setCookie, 'webauthn-session')

            options = {'publicKey': resp.json()}

            #  User holds an authenticator
            attestation = self.device.get(options, 'https://localhost:8081')

        resp = post('/user/login',
                    {"user_name": (None, self.username),
                     "username": (None, self.username),
                     "password": (None, self.password),
                     "assertion": (None, json.dumps(attestation)),
                    },
                    cookies=self.cookies,
        )

        if resp.status_code != 200:
            print("Error in login")
            return

        resp = get('/')

        # Set the `csrf` cookie
        setCookie = resp.headers['Set-Cookie']
        self.cookies['_csrf'] = getCookie(setCookie, '_csrf')

        print("Successfully logged in user!")

    def gogs_server_registration(self):  # pylint: disable=redefined-outer-name
        """Registration example"""
        # Begin registration
        resp = post('/webauthn/begin_register',
                    {"username": (None, self.username)},
                    cookies=self.cookies
        )
        
        if resp.status_code != 200:
            print("Error in begin_register")
            return

        # Set the `webauthn-session` cookie
        setCookie = resp.headers['Set-Cookie']
        self.cookies['webauthn-session'] = getCookie(setCookie, 'webauthn-session')

        options = {'publicKey': resp.json()}

        # User holds an authenticator.
        #
        # NOTE: SoftWebauthnDevice emulates mixed client and authenticator behavior
        # and can be used for testing Webauthn/FIDO2 enabled applications during
        # continuous integration test-cases.
        attestation = self.device.create(options, 'https://localhost:8081')

        resp = post('/webauthn/finish_register',
                    {"username": (None, self.username),
                     "credentials": (None, json.dumps(attestation)),
                    },
                    cookies=self.cookies,
        )

        if resp.status_code == 200:
            print("Successfully registered webauthn user!")
        else:
            print("Error in register webauthn user")

    def gogs_server_change_email(self, newEmail):
        auth_text = "Confirm profile details: username {} email {}".format(self.username, newEmail)

        resp = post('/webauthn/begin_attestation',
                    {"auth_text": (None, auth_text)},
                    cookies=self.cookies
        )

        if resp.status_code != 200:
            print("Error in begin_attestation")
            return

        # Set the `webauthn-session` cookie
        setCookie = resp.headers['Set-Cookie']
        self.cookies['webauthn-session'] = getCookie(setCookie, 'webauthn-session')

        options = {'publicKey': resp.json()}

        #  User holds an authenticator
        attestation = self.device.get(options, 'https://localhost:8081')

        # Time this POST request
        t0 = time.time()
        resp = post('/user/settings',
                    {"_csrf": (None, self.cookies['_csrf']),
                     "name": (None, self.username),
                     "full_name": (None, ""),
                     "email": (None, newEmail),
                     "website": (None, ""),
                     "location": (None, ""),
                     "auth_text": (None, auth_text),
                     "assertion": (None, json.dumps(attestation)),
                    },
                    cookies=self.cookies,
        )
        elapsed_time = time.time() - t0

        if resp.status_code != 200:
            print("Error in change user email")

        # In milliseconds
        return elapsed_time * 1000

def change_emails(user, n_iters, queue):
    run_times = []

    for i in range(n_iters):
        rt = user.gogs_server_change_email("email@email{}.com".format(i))
        run_times.append(rt)

        if i % 100 == 0:
            print("=== User {} \t Iters {} \t Avg time: {} ms ===".format(user.username, i, np.mean(run_times)))

    # Place all of the `run_times` into the `queue`
    for rt in run_times:
        queue.put(rt)

if __name__ == '__main__':
    n_users = 8
    n_iters = 500
    percentile = 95

    users = []

    # Load the `users` if they exist
    usersFiles = './users.pkl'
    if os.path.exists(usersFiles):
        with open(usersFiles, 'rb') as infile:
            users = pickle.load(infile)
    else:
        # Initialize the new `User`s
        for u in range(n_users):
            username = 'durian{}'.format(u)
            users.append(User(username, 'password'))

    # Initialize a `queue` to collect all of the run times
    queue = Queue()
    procs = [Process(target=change_emails, 
                     kwargs={'user': users[u], 'n_iters': n_iters, 'queue': queue}) 
             for u in range(n_users)]
    # procs = []
    # for u in range(n_users):
    #     user = users[0]

    #     def target():
    #         print("User: ", user.username)
    #         change_emails(user, n_iters, queue)

    #     procs.append(Process(target=target))

    for p in procs:
        p.start()

    for p in procs:
        p.join()

    # Collect the `run_times`
    run_times = []
    while not queue.empty():
        run_times.append(queue.get())

    #print(run_times)
    
    # Get the `percentile` from the `run_times`
    print("{}th percentile: {}".format(
        percentile,
        np.percentile(run_times, percentile))
    )
    
    # durian = users['durian']
    # print(durian.is_webauthn_enabled())

    # for i in range(100):
    #     durian.gogs_server_change_email("email@email{}.com".format(i))
    
    # TODO: Pickle does not want to serialize the private_key
    #
    # Write the `users` to file
    #with open(usersFiles, 'wb') as outfile:
    #    pickle.dump(users, outfile)
