
import os

import sqlite3

def clear_webauthn_entries():
    conn = sqlite3.connect('/home/damian/Documents/Educational/MEng/webauthn-firewall/webauthn-firewall.db')
    conn.execute('delete from webauthn_entries ;')
    conn.commit()
    conn.close()

def main():
    for n_users in range(1, 30 + 1):
        clear_webauthn_entries()
        os.system('python3.6 test_gogs.py {}'.format(n_users))

if __name__ == '__main__':
    main()
