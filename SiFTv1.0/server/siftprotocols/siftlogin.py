# python3

from time import time_ns
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None

    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users

    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):

        login_req_str = str(login_req_struct['timestamp']) + self.delimiter
        login_req_str += login_req_struct['username'] + self.delimiter
        login_req_str += login_req_struct['password'] + self.delimiter
        login_req_str += login_req_struct['client_random'].hex()

        return login_req_str.encode(self.coding)

    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['timestamp'] = int(login_req_fields[0])
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = bytes.fromhex(login_req_fields[3])

        return login_req_struct

    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):

        login_res_str = login_res_struct['request_hash'].hex() + self.delimiter
        login_res_str += login_res_struct['server_random'].hex()

        return login_res_str.encode(self.coding)

    # parses a login response into a dictionary
    def parse_login_res(self, login_res):

        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1])

        return login_res_struct

    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(
            password=pwd,
            salt=usr_struct['salt'],
            dkLen=len(usr_struct['pwdhash']),
            count=usr_struct['icount'],
            hmac_hash_module=SHA256)

        return pwdhash == usr_struct['pwdhash']

    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].hex())
            print('------------------------------------------')
        # DEBUG

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        login_req_struct = self.parse_login_req(msg_payload)
        time = login_req_struct['timestamp']
        user = login_req_struct['username']
        pwd = login_req_struct['password']
        client_random = login_req_struct['client_random']

        # verifying timestamp by server
        curr_time = time_ns()
        least = curr_time - 10 ** 9
        most = curr_time + 10 ** 9

        if time < least or time > most:
            raise SiFT_LOGIN_Error('Message is not fresh')

        # checking username and password
        if user in self.server_users:
            if not self.check_password(pwd, self.server_users[user]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unknown user attempted to log in')

        # compute hash of payload of received login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # building login response
        server_random = get_random_bytes(16)

        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = server_random

        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].hex())
            print('------------------------------------------')
        # DEBUG

        # trying to send login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # all verifications successful
        # derivation of transfer key by server
        try:
            final_key = client_random + server_random
            final_key = HKDF(
                master=final_key,
                salt=request_hash,
                key_len=32,
                num_keys=1,
                hashmod=SHA256
            )
            # passing the transfer key to mtp
            self.mtp.set_transfer_key(final_key)
        except:
            raise SiFT_MTP_Error('Unable to establish a shared secret')

        # DEBUG
        if self.DEBUG:
            print('User ' + user + ' logged in')
        # DEBUG

        return user

    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):

        # building a login request
        client_random = get_random_bytes(16)

        login_req_struct = {}

        # client creating timestamp
        login_req_struct['timestamp'] = time_ns()

        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['client_random'] = client_random

        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode(self.coding))
            print('------------------------------------------')
        # DEBUG

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # compute hash of payload and store to verify later
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        stored_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].hex())
            print('------------------------------------------')
        # DEBUG

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)
        request_hash = login_res_struct['request_hash']
        server_random = login_res_struct['server_random']

        # checking request_hash received in the login response
        if request_hash != stored_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # all verifications successful
        # derivation of final transfer key by client
        try:
            final_key = client_random + server_random
            final_key = HKDF(
                master=final_key,
                salt=request_hash,
                key_len=32,
                num_keys=1,
                hashmod=SHA256
            )
            # passing the transfer key to mtp
            self.mtp.set_transfer_key(final_key)
        except:
            raise SiFT_MTP_Error('Unable to establish a shared secret')
