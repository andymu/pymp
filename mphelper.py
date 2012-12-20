#-------------------------------------------------------------------------------
# Name: mphelper.py
# Purpose: Utilities for Mobile Payment
#
# Author:      Mu Hongyu
#
# Created:     31-10-2012
# Copyright:   (c) hmu 2012
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import binascii
import struct

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib

from pyDes import *


################################################################################
## Common routines
################################################################################
def trim(s):
    return ''.join(re.split('\W+',s))

def XORFF(str_arr):
    by_arr = binascii.unhexlify(str_arr)
    by_arr_xor_ff = ''
    for v in by_arr:
        by_arr_xor_ff += struct.pack('B', ord(v) ^ 0xFF)

    return binascii.hexlify(by_arr_xor_ff).upper()

def XOR_HEXSTR(A, B):

    X = A
    Y = B

    if len(A) > len(B):
        X = B
        Y = A

    x_hex = binascii.unhexlify(X)
    y_hex = binascii.unhexlify(Y)
    a_xor_b = ''
    i = 0
    for v in x_hex:
        a_xor_b += struct.pack('B', ord(v) ^ ord(y_hex[i]))
        i += 1

    return binascii.hexlify(a_xor_b).upper()

def XOR_BYTE(A, B):

    i = 0
    a_xor_b = ''

    X = A
    Y = B

    if len(A) > len(B):
        X = B
        Y = A

    for v in X:
        a_xor_b += struct.pack('B', ord(v) ^ ord(Y[i]))
        i += 1

    return a_xor_b


def PADDING80(data, block_size):
        dv = binascii.unhexlify(data)
        dv += '\x80'
        dl = len(dv)
        tail = dl % block_size
        if tail != 0:
            pl = block_size - dl%block_size
            dv += '\x00' * pl
        return binascii.hexlify(dv).upper()

def APPEND_LV(buff, itm):
        if itm is None:
            buff += '00'
        else:
            buff += '%02X%s' % (len(itm)/2, itm)

        return buff

def DES_3DES_CBC_MAC(key, icv, msg):
        k = binascii.unhexlify(key)
        iv = binascii.unhexlify(icv)
        data = binascii.unhexlify(msg)

        des_key = des(k[:8], ECB, None, None, PAD_NORMAL)
        tdes_key = triple_des(k, ECB, None, None, PAD_NORMAL)

        len_des_data = len(data[:-8])

        c = iv
        off = 0
        while len_des_data > 0:
            m = XOR_BYTE(c, data[off:off+8])
            c = des_key.encrypt(m)
            len_des_data -= 8
            off += 8

        m = XOR_BYTE(c, data[off:off+8])
        c = tdes_key.encrypt(m)

        return binascii.hexlify(c).upper()

def DES3_CBC_ENC(key, icv, msg):
    k = binascii.unhexlify(key)
    m = binascii.unhexlify(msg)
    iv = binascii.unhexlify(icv)
    cipher = triple_des(k, CBC, iv, None, PAD_NORMAL)
    c = cipher.encrypt(m)
    return binascii.hexlify(c).upper()

def DES3_ECB_ENC(key, msg):
    k = binascii.unhexlify(key)
    m = binascii.unhexlify(msg)
    cipher = triple_des(k, ECB, None, None, PAD_NORMAL)
    c = cipher.encrypt(m)
    return binascii.hexlify(c).upper()
    
def DES3_ECB_DEC(key, cipher):
    k = binascii.unhexlify(key)
    c = binascii.unhexlify(cipher)
    cipher = triple_des(k, ECB, None, None, PAD_NORMAL)
    m = cipher.decrypt(c)
    return binascii.hexlify(m).upper()

def DES_ECB_ENC(key, msg):
    k = binascii.unhexlify(key)
    m = binascii.unhexlify(msg)
    cipher = des(k, ECB, None, None, PAD_NORMAL)
    c = cipher.encrypt(m)
    return binascii.hexlify(c).upper()

def RSA_ENC(n, e, msg):
    pass

def RSA_DEC(n, e, msg):
    pass

def RSA_VERIFY_SIGNATURE(n, e, msg):
    pass

def RSA_SIGN(RSA_N, RSA_E, RSA_D, msg, log = False):
    '''
        sha-1 hash algorithm
        sign data with PKCS15 mode
        Input parameters:

            RSA_N, RSA_E, RSA_D is big integer
            msg is string, e.g. '1020304050607080'
    '''
    if log:
        print '------------------------------RSA------------------------------'
        print 'N:\n' + hex(RSA_N).upper() + '\nE:\n' + hex(RSA_E).upper() + '\nD:\n' + hex(RSA_D).upper() + '\n'
        print 'Message:\n' + msg + '\n'
    h = SHA.new(binascii.unhexlify(msg))

    k = RSA.construct((RSA_N, RSA_E, RSA_D))

    s = PKCS1_v1_5.new(k)

    sig = s.sign(h)

    sig_str = binascii.hexlify(sig).upper()

    if log:
        print 'Signature:\n' + sig_str + '\n'

    return sig_str
    
    
def GET_TLV_LIST(tlvs):
    '''
        Input format:
            TLV|TLV|TLV...|TLV
        TLV's Format:
            T(1 byte) | L(1 byte) | V(L bytes)
    '''
    tlvList = []
    end = len(tlvs)
    off = 0
    str = tlvs
    while len(str) > 0:
        T = str[:2]
        L = str[2:4]
        l = int(str[2:4], 16)
        V = str[4:4+l*2]
        tlvList.append((T, L, V))
        str = str[4+l*2:]
    
    return tlvList

def main():
    tlvs = '8101198204001371AD830243F8'
    print PARSETLV(tlvs)


if __name__ == '__main__':
    main()
