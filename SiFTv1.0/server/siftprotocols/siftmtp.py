# python3

import socket

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:
    
    def __init__(self, peer_socket):

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
        self.msg_types = (self.type_login_req, self.type_login_res,
                        self.type_command_req, self.type_command_res,
                        self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
                        self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
        # --------- STATE ------------
        self.peer_socket = peer_socket
        self.snd_sqn = 1
        self.rcv_sqn = 0
        # TODO
        # need actual secret key
        self.transfer_key = None

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

    # receives and parses message, returns msg_type and msg_payload
    def receive_msg(self):

        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message header received')

        parsed_msg_hdr = self.parse_msg_header(msg_hdr)
        msg_type = parsed_msg_hdr['typ']
        
        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if msg_type not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')
        
        if self.transfer_key is None:
            self.transfer_key = b'server.py is the server program.'
        
        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
        
        msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
        if msg_sqn <= self.rcv_sqn:
            raise SiFT_MTP_Error(f'Message replay (old sequence detected): {msg_sqn} <= {self.rcv_sqn}')
        
        # is_login = msg_type == self.type_login_req
        # etk_len = 256 if is_login else 0
        
        # try to receive
        try:
            msg_body_len = msg_len - self.size_msg_hdr
            msg_body = self.receive_bytes(msg_body_len)
            
            # if is_login:
            #     if msg_body_len != self.size_mac + etk_len:
            #         raise SiFT_MTP_Error('Incomplete message body received')
            #     epd_len = msg_body_len - self.size_mac - etk_len
            #     epd = msg_body[:epd_len] # includes an additional etk
            #     mac = msg_body[epd_len:epd_len + self.size_mac:]
            #     # TODO
            #     # use etk later to decrupt tk with RSA
            #     # then use tk to decrypt epd for login msg
            #     etk = msg_body[epd_len + self.size_mac:]
            # else:
            #     epd = msg_body[:-self.size_mac]
            #     mac = msg_body[-self.size_mac:]
            
            epd = msg_body[:-self.size_mac]
            mac = msg_body[-self.size_mac:]
            
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
            cipher = AES.new(self.transfer_key, 
                            AES.MODE_GCM,
                            nonce = nonce,
                            mac_len = self.size_mac)
            cipher.update(msg_hdr)
            msg_payload = cipher.decrypt_and_verify(epd, mac)
        
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('MTP message received (' + str(msg_len) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(len(msg_body)) + '): ')
            print(msg_body.hex())
            print('------------------------------------------')
        # DEBUG

        if len(msg_body) != msg_len - self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message body received')

        self.rcv_sqn = msg_sqn

        return msg_type, msg_payload
    
    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):
        
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    # builds and sends message of a given type using the provided payload
    def send_msg(self, msg_type, msg_payload):
        
        # TODO
        # check for login request
        # is_login = msg_type == self.type_login_req
        # etk = b''
        
        # if is_login:
        #     # tk = get_random_bytes(32)
        #     if self.transfer_key is None:
        #         self.transfer_key = b'server.py is the server program.'
        #     etk = b'\x00' * 256 # total_msg_len += 256
        #     msg_len = self.size_msg_hdr + len(msg_payload) + self.size_mac + len(etk)
        # else:
        #     msg_len = self.size_msg_hdr + len(msg_payload) + self.size_mac
        
        # ??? msg_len before and after encrypt? 
        # ex: bob\nbbb = 9 = pd_len
        # total msg_len = 35 = msg_hdr (16) + pd_len (7) + msg_body (19)
        # currently print len in msg_hdr is 23 (not the same?1)
        msg_len = self.size_msg_hdr + len(msg_payload) + self.size_mac
        msg_len_bytes = msg_len.to_bytes(2, 'big')
        msg_sqn_bytes = self.snd_sqn.to_bytes(2, 'big')
        msg_hdr_rnd = get_random_bytes(6)

        msg_hdr = self.msg_hdr_ver + msg_type + msg_len_bytes + msg_sqn_bytes + msg_hdr_rnd + self.msg_hdr_rsv
        
        # if is_login:
        #     AES_key = tk
        # else:
        #     AES_key = self.transfer_key
        
        if self.transfer_key is None:
            self.transfer_key = b'server.py is the server program.'
        nonce = msg_sqn_bytes + msg_hdr_rnd
        cipher = AES.new(self.transfer_key,
                        AES.MODE_GCM, 
                        nonce = nonce, 
                        mac_len = self.size_mac)
        cipher.update(msg_hdr)
        ciphertext, mac = cipher.encrypt_and_digest(msg_payload)

        # TODO
        # if is_login:
            # Check for server RSA public key
            # ---
            # keypair = RSA.generate(2048)
            # pubkey = keypair.publickey()
            # cipher = PKCS1_OAEP.new(pubkey)
            # etk = cipher.encrypt(tk)
        
        # build message
        msg = msg_hdr + ciphertext + mac 
        # if is_login: msg += etk
        msg_size = len(msg)

        # DEBUG
        if self.DEBUG:
            print('MTP message to send (' + str(msg_size) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(msg_size) + '): ')
            print(msg.hex())
            print('------------------------------------------')
        # DEBUG

        # try to send
        try:
            self.send_bytes(msg)
            self.snd_sqn += 1
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
