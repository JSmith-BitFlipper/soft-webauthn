"""SoftWebauthnDevice usage for (yubico's) fido2 example webserver/application"""

# Disable the HTTPs verify warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import pytest
import json
import pickle

from multiprocessing import Process, Queue, Pipe
import time
import os

import numpy as np

# Hacky way to import `soft_webauthn`
import sys
sys.path.append("..")

from soft_webauthn import SoftWebauthnDevice

ADDRESS = 'https://localhost:8081'

def findTrim(s, findStr):
    return s.find(findStr) + len(findStr)

def getCookie(setCookie, cookieName):
    idx1 = findTrim(setCookie, cookieName) + 1 # +1 to rid of =
    idx2 = findTrim(setCookie[idx1:], ';') - 1 # -1 to rid of ;
    return setCookie[idx1:idx1+idx2]

def get(url):
    return requests.get(ADDRESS + url,
                        verify=False)

def post(url, data, cookies=dict()):
    return requests.post(ADDRESS + url,
                         files=data,
                         cookies=cookies,
                         verify=False)

class User():
    def __init__(self, username, password, useWebauthn):
        self.cookies = dict()
        
        # Remember the input arguments
        self.username = username
        self.password = password
        self.useWebauthn = useWebauthn

        # Generate a new device for this `User`
        self.device = SoftWebauthnDevice()

        # Persistent variables for the functions
        self._change_email_prev_t0 = time.time()
        self._change_email_prev_t1 = time.time()
        
        # Log the user in and webauthn register them (if necessary)
        self.log_in_and_register()

    def log_in_and_register(self):
        self.gogs_server_login()

        # Register only if the user does not have webauthn enabled
        if self.useWebauthn and not self.is_webauthn_enabled():
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

        attestation = "no-attestation"
        # If webauthn is enabled, generate an `assertion` object
        if self.useWebauthn and self.is_webauthn_enabled():
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

        #print("Successfully logged in user!")

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
            #print("Successfully registered webauthn user!")
            pass
        else:
            print("Error in register webauthn user")

    def gogs_server_change_email(self, newEmail):
        auth_text = "Confirm profile details: username {} email {}".format(self.username, newEmail)

        attestation = "no-attestation"
        if self.useWebauthn:
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

        prev_run_time = self._change_email_prev_t1 - self._change_email_prev_t0
        time_since_last_POST = time.time() - self._change_email_prev_t0

        # Sleep so that each POST request is approximately sent every 500ms
        #time.sleep(max(0.5 - (time_since_last_POST + prev_run_time), 0))

        # Time this POST request
        t0 = time.time()
        self._change_email_prev_t0 = t0
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

        #resp = get('/user/settings')

        t1 = time.time()
        self._change_email_prev_t1 = t1

        # Save the `elapsed_time`
        elapsed_time = t1 - t0
        self._change_email_prev_run_time = elapsed_time

        if resp.status_code != 200:
            print("Error in change user email")

        # In milliseconds
        return elapsed_time * 1000, t1
        #return resp.elapsed.total_seconds() * 1000, t1

def change_emails(user, n_iters, queue):
    run_times = []
    diff_post_times = []
    prev_post_time = time.time()

    for i in range(n_iters):
        rt, end_post_time = user.gogs_server_change_email("email@email{}.com".format(i))

        # Append the timings
        run_times.append(rt)
        diff_post_times.append((end_post_time - prev_post_time) * 1000)
        prev_post_time = end_post_time

        if i % 50 == 0:
            #print("=== User {} \t Iters {} \t Avg time: {:0.2f} ms \t Avg between POST: {:0.2f} ms ===".format(
            #    user.username, i, np.mean(run_times), np.mean(diff_post_times)))
            pass

    # Place all of the `run_times` into the `queue`
    for rt in run_times:
        queue.put(rt)

def run_times_aggregator(percentile, queue, pipe):
    # Collect the `run_times`
    run_times = []

    # The `pipe` is still empty, so no kill signal received yet
    while not pipe.poll():
        # Continue emptying the `queue`
        while not queue.empty():
            run_times.append(queue.get())
    
    # Get the `percentile` from the `run_times`
    print("{}th percentile: {}".format(
        percentile,
        np.percentile(run_times, percentile))
    )


def create_accounts(lo, hi):
    """ Create user accounts 'durian{id}' where `id` is in [lo, hi) """
    for i in range(lo, hi):
        username = 'durian{}'.format(i)
        email = 'test{}@email.com'.format(i)

        resp = post('/user/sign_up',
                    {"_csrf": (None, "no-csrf"),
                     "user_name": (None, username),
                     "email": (None, email),
                     "password": (None, "password"),
                     "retype": (None, "password"),
                    }
        )

        if resp.status_code != 200:
            print("Error in creating new user")

        #print("Created user: {}".format(username))

def main():
    # Create a bunch of new users
    if False:
        create_accounts(18, 128)
        return

    useWebauthn = False
    n_users = int(sys.argv[1])
    n_iters = 300
    percentile = 95

    print("Running {} user(s)".format(n_users))

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
            users.append(User(username, 'password', useWebauthn))

    # Initialize a `queue` to collect all of the run times
    queue = Queue()
    procs = [Process(target=change_emails, 
                     args=(users[u], n_iters, queue,)) 
             for u in range(n_users)]

    parent_conn, child_conn = Pipe()
    aggregator = Process(target=run_times_aggregator,
                         args=(percentile, queue, child_conn,))
    # procs = []
    # for u in range(n_users):
    #     user = users[0]

    #     def target():
    #         print("User: ", user.username)
    #         change_emails(user, n_iters, queue)

    #     procs.append(Process(target=target))

    for p in procs:
        p.start()

    aggregator.start()

    for p in procs:
        p.join()

    # Send over the kill signal to the `aggregator`
    parent_conn.send(True)

    # Wait for the aggregator to finish
    aggregator.join()
    
    # durian = users['durian']
    # print(durian.is_webauthn_enabled())

    # for i in range(100):
    #     durian.gogs_server_change_email("email@email{}.com".format(i))
    
    # TODO: Pickle does not want to serialize the private_key
    #
    # Write the `users` to file
    #with open(usersFiles, 'wb') as outfile:
    #    pickle.dump(users, outfile)

if __name__ == '__main__':
    main()
