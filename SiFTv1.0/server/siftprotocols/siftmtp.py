# python3

from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:

    def __init__(self, peer_socket, rsa_key):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b'\x01\x00'
        self.msg_hdr_rsv = b'\x00\x00'

        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2
        self.size_mac = 12
        self.size_etk = 256

        self.type_login_req = b'\x00\x00'
        self.type_login_res = b'\x00\x10'
        self.type_command_req = b'\x01\x00'
        self.type_command_res = b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res = b'\x02\x10'
        self.type_dnload_req = b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'

        self.msg_types = (
            self.type_login_req,
            self.type_login_res,
            self.type_command_req,
            self.type_command_res,
            self.type_upload_req_1,
            self.type_upload_req_0,
            self.type_upload_res,
            self.type_dnload_req,
            self.type_dnload_res_0,
            self.type_dnload_res_1
        )
        # --------- STATE ------------
        self.peer_socket = peer_socket

        if isinstance(rsa_key, RsaKey):
            self.server_publickey = rsa_key
            if rsa_key.has_private:
                self.server_privatekey = rsa_key

        self.snd_sqn = 1
        self.rcv_sqn = 0
        self.tk = None
        self.transfer_key = None

    # get the derived final transfer key
    def set_transfer_key(self, final_key):
        self.transfer_key = final_key

    # parses a message header and returns a dictionary containing the header fields
    def parse_msg_header(self, msg_hdr):

        parsed_msg_hdr, i = {}, 0
        parsed_msg_hdr['ver'], i = msg_hdr[i:i + self.size_msg_hdr_ver], i + self.size_msg_hdr_ver
        parsed_msg_hdr['typ'], i = msg_hdr[i:i + self.size_msg_hdr_typ], i + self.size_msg_hdr_typ
        parsed_msg_hdr['len'], i = msg_hdr[i:i + self.size_msg_hdr_len], i + self.size_msg_hdr_len
        parsed_msg_hdr['sqn'], i = msg_hdr[i:i + self.size_msg_hdr_sqn], i + self.size_msg_hdr_sqn
        parsed_msg_hdr['rnd'], i = msg_hdr[i:i + self.size_msg_hdr_rnd], i + self.size_msg_hdr_rnd
        parsed_msg_hdr['rsv'] = msg_hdr[i:i + self.size_msg_hdr_rsv]

        return parsed_msg_hdr

    # receives n bytes from the peer socket
    def receive_bytes(self, n):

        bytes_received = b''
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n - bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')
            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received += chunk
            bytes_count += len(chunk)

        return bytes_received

    # receives and parses message, returns msg_type and msg_payload using gcm mode
    def receive_msg(self):

        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message header received')

        # parse header
        parsed_msg_hdr = self.parse_msg_header(msg_hdr)
        msg_type = parsed_msg_hdr['typ']
        msg_len = int.from_bytes(parsed_msg_hdr['len'], 'big')
        msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], 'big')

        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if msg_type not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')

        # check sequence number in header
        if msg_sqn <= self.rcv_sqn:
            raise SiFT_MTP_Error(f'Message replay (old sequence detected): {msg_sqn} <= {self.rcv_sqn}')

        # try to receive message
        try:
            msg_body_len = msg_len - self.size_msg_hdr
            msg_body = self.receive_bytes(msg_body_len)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

        if len(msg_body) != msg_len - self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message body received')

        # recreate nonce
        nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']

        # processing the login request by server
        if msg_type == self.type_login_req:
            if self.server_privatekey is None:
                raise SiFT_MTP_Error('Server missing private key to decrypt ETK')

            # parse message body
            epd_len = msg_body_len - self.size_mac - self.size_etk
            epd = msg_body[:epd_len]
            mac = msg_body[epd_len:epd_len + self.size_mac]
            etk = msg_body[-self.size_etk:]

            # use private key to decrypt etk (to authenticate server)
            try:
                cipher_rsa = PKCS1_OAEP.new(self.server_privatekey)
            except Exception:
                raise SiFT_MTP_Error('Server missing private key for login request')

            try:
                self.tk = cipher_rsa.decrypt(etk)
            except Exception:
                raise SiFT_MTP_Error('Invalid ETK (RSA decryption failed)')

            # use tk to verify mac and decrypt epd
            try:
                cipher = AES.new(self.tk, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
                cipher.update(msg_hdr)
                msg_payload = cipher.decrypt_and_verify(epd, mac)
            except:
                raise SiFT_MTP_Error('Invalid MAC in login request')

        # creating the login response by server

        elif msg_type == self.type_login_res:
            # get login response message body
            epd = msg_body[:-self.size_mac]
            mac = msg_body[-self.size_mac:]

            # decrypt payload
            try:
                cipher = AES.new(self.tk, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
                cipher.update(msg_hdr)
                msg_payload = cipher.decrypt_and_verify(epd, mac)
            except:
                raise SiFT_MTP_Error('Invalid MAC in login response')

        else:
            # get subsequent message body
            epd = msg_body[:-self.size_mac]
            mac = msg_body[-self.size_mac:]

            # decrypt payload with final transfer key
            try:
                cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
                cipher.update(msg_hdr)
                msg_payload = cipher.decrypt_and_verify(epd, mac)
            except:
                raise SiFT_MTP_Error('Invalid MAC in message')

        # DEBUG
        if self.DEBUG:
            print('MTP message received (' + str(msg_len) + '):')
            print('HDR (' + str(self.size_msg_hdr) + '): ' + msg_hdr.hex())
            print('EPD (' + str(len(epd)) + '): ' + epd.hex())
            print('MAC (' + str(self.size_mac) + '): ' + mac.hex())
            if msg_type == self.type_login_req:
                print('ETK (' + str(self.size_etk) + '): ' + etk.hex())
            print('------------------------------------------')

        # updating receive sequence number
        self.rcv_sqn = msg_sqn

        return msg_type, msg_payload

    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):

        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    # builds and sends message of a given type using the provided payload using gcm mode
    def send_msg(self, msg_type, msg_payload):

        # create nonce
        msg_sqn_bytes = self.snd_sqn.to_bytes(2, 'big')
        msg_hdr_rnd = get_random_bytes(6)
        nonce = msg_sqn_bytes + msg_hdr_rnd

        # default message length
        msg_len = self.size_msg_hdr + len(msg_payload) + self.size_mac

        # default header
        msg_hdr = (
                self.msg_hdr_ver +
                msg_type +
                msg_len.to_bytes(2, 'big') +
                msg_sqn_bytes +
                msg_hdr_rnd +
                self.msg_hdr_rsv
        )

        msg = b''

        # creating the login request by client
        if msg_type == self.type_login_req:
            if self.server_publickey is None:
                raise SiFT_MTP_Error('Client missing server public key for login request')

            # generation of temp transfer key for login session by client
            self.tk = get_random_bytes(32)

            # update header with new message length
            msg_len += self.size_etk
            before_hdr_len = self.size_msg_hdr_ver + self.size_msg_hdr_ver
            msg_hdr = (
                    msg_hdr[:before_hdr_len] +
                    msg_len.to_bytes(2, 'big') +
                    msg_hdr[before_hdr_len + self.size_msg_hdr_len:]
            )

            # encrypt payload using AES-GCM with tk
            cipher = AES.new(self.tk, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
            cipher.update(msg_hdr)
            ciphertext, mac = cipher.encrypt_and_digest(msg_payload)

            # use server RSA public key to encrypt tk
            cipher = PKCS1_OAEP.new(self.server_publickey)
            etk = cipher.encrypt(self.tk)

            # build encrypted login message
            msg = msg_hdr + ciphertext + mac + etk


        # processing the login response by client
        elif msg_type == self.type_login_res:
            # encrypt payload using AES-GCM with tk
            cipher = AES.new(self.tk, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
            cipher.update(msg_hdr)
            ciphertext, mac = cipher.encrypt_and_digest(msg_payload)

            # build encrypted login response
            msg = msg_hdr + ciphertext + mac

        else:
            # encrypt payload with final transfer key
            cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
            cipher.update(msg_hdr)
            ciphertext, mac = cipher.encrypt_and_digest(msg_payload)

            # build subsequent encrypted message
            msg = msg_hdr + ciphertext + mac

        # DEBUG
        if self.DEBUG:
            print('MTP message to send (' + str(msg_len) + '):')
            print('HDR (' + str(self.size_msg_hdr) + '): ' + msg_hdr.hex())
            print('EPD (' + str(len(ciphertext)) + '): ' + ciphertext.hex())
            print('MAC (' + str(self.size_mac) + '): ' + mac.hex())

            if msg_type == self.type_login_req:
                print('ETK (' + str(self.size_etk) + '): ' + etk.hex())
            print('------------------------------------------')
        # DEBUG

        # try to send message
        try:
            self.send_bytes(msg)

            # updating of sqn number if message sent successfully
            self.snd_sqn += 1
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
