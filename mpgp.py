#-------------------------------------------------------------------------------
# Name: mpgp.py
# Purpose: To provide GP 2.2.1 implementation

# Author:      Mu Hongyu Andy
#
# Created:     15-10-2012
# Copyright:   (c) hmu 2012
# Licence:     <your licence>
#-------------------------------------------------------------------------------

#! /usr/bin/env python

import sys
import re
import binascii
import struct

from mphelper import *

DES_BLOCK_SIZE = 8

class GPImpl():
    def __init__(self, scmgr, CARD_PROFILE = None, loggerHandle = None):

        # Instance of Smart Card Reader Management
        self.mgr = scmgr

        self.logger = loggerHandle

        # returned by Initial Update
        self.keyInfo = None
        self.sequenceCounter = None
        self.cardChallenge = None
        self.cardCryptogram = None

        # C-MAC length
        self.CMAC_LEN = 8

        # Initial chaining vector
        self.hostMAC = '00' * DES_BLOCK_SIZE

        if not self.mgr.isRdrOpened():
            raise Exception('Reader not connected!')

        # Terminal configuration
        if CARD_PROFILE is None:
            self.KMC = '404142434445464748494A4B4C4D4E4F'
            self.KV = '20'
            self.SL = '00'
            self.CPG = 0
            self.SCP = 2
            self.SCP_i = 15
        else:
            self.KMC = CARD_PROFILE['KMC']
            self.KV = CARD_PROFILE['KEY_VERSION']
            self.SL = CARD_PROFILE['SECURITY_LEVEL']
            self.CPG = CARD_PROFILE['CPG']
            self.SCP = CARD_PROFILE['SCP']
            self.SCP_i = CARD_PROFILE['SCP_i']

    def log(self, msg):
        if self.logger is not None:
            self.logger.write(msg)

    def _initialUpdate(self, hostChallenge):
        self.log('------------------------------Initial Update---------------------')
        INIT_UPD = '8050' + self.KV + '00' + ('%02X' % (len(hostChallenge)/2)) + hostChallenge

        resp_tup = self.mgr.transmitAPDU(INIT_UPD)

        resp = resp_tup[0]
        self.keyInfo = resp[20:24]
        self.sequenceCounter = resp[24:28]
        self.cardChallenge = resp[28:40]
        self.cardCryptogram = resp[40:56]

        self.keyDiversData = resp[:20]

        self.keyDivers = resp[8:20]

    def _diversifyKey(self, KMC, keyDiversFactor=None, seqCounter=None, CPG = 0, SCP = 2, i=15):

        KDCenc = KMC
        KDCmac = KMC
        KDCkek = KMC

        CSN_IC_BATCH_ID = binascii.unhexlify(keyDiversFactor)

        self.log('----------------------------------------------------------------')
        self.log('\tKMC: ' + KMC)
        self.log('\tKey Diversification:')

        # Derive KMC
        if CPG == 0:
            self.log('NO')

        elif CPG == 202:
            self.log('CPG202\n')
            raise Exception('CPG202 not supported temporarily')

        elif CPG == 212:
            self.log('CPG212\n')
            cpg212DiversEncDi = keyDiversFactor + 'F001' + keyDiversFactor + '0F01'
            cpg212DiversMACDi = keyDiversFactor + 'F002' + keyDiversFactor + '0F02'
            cpg212DiversKekDi = keyDiversFactor + 'F003' + keyDiversFactor + '0F03'

            KDCenc = DES3_CBC_ENC(KMC, '00' * 8, cpg212DiversEncDi)
            KDCmac = DES3_CBC_ENC(KMC, '00' * 8, cpg212DiversMACDi)
            KDCkek = DES3_CBC_ENC(KMC, '00' * 8, cpg212DiversKekDi)

            self.log('\tFactor:' + cpg212DiversEncDi)
            self.log('\tKDCenc:' + KDCenc)

            self.log('------------------------------------------------------------')
            self.log('\tFactor:' + cpg212DiversMACDi)
            self.log('\tKDCmac:' + KDCmac)

            self.log('------------------------------------------------------------')
            self.log('\tFactor:' + cpg212DiversKekDi)
            self.log('\tKDCkek:' + KDCkek)


        self.log('\n\tSCP%02X i=%d\n' % (SCP, i))

        # Gnerate secure channel session key

        if SCP == 2:
            scp02DiversENCDi = '0182' + seqCounter + '00' * 12
            scp02DiversMACDi = '0101' + seqCounter + '00' * 12
            scp02DiversDEKDi = '0181' + seqCounter + '00' * 12

            SK_ENC = DES3_CBC_ENC(KDCenc, '00' * DES_BLOCK_SIZE, scp02DiversENCDi)
            self.log('\tKDCenc:' + KDCenc)
            self.log('\tFactor:' + scp02DiversENCDi)
            self.log('\tS-ENC :' + SK_ENC)

            SK_MAC = DES3_CBC_ENC(KDCmac, '00' * DES_BLOCK_SIZE, scp02DiversMACDi)
            self.log('\tKDCmac:' + KDCmac)
            self.log('\tFactor:' + scp02DiversMACDi)
            self.log('\tS-MAC :' + SK_MAC)

            SK_DEK = DES3_CBC_ENC(KDCkek, '00' * DES_BLOCK_SIZE, scp02DiversDEKDi)
            self.log('\tKDCkek:' + KDCkek)
            self.log('\tFactor:' + scp02DiversDEKDi)
            self.log('\tDEK :' + SK_DEK)

        elif SCP == 1:
            self.log('SCP 01 not supported')
        else:
            self.log('SCP %d not supported' % SCP)

        self.log('\n\tSecurity Level: ' + self.SL)

        self.log('\n---------------------------------------------------------------')

        # check card cryptogram
        return (SK_ENC, SK_MAC, SK_DEK)

    def encryptKey(self, key):
        return DES3_ECB_ENC(self.DEK, key)

    def rawAPDU(self, apdu):
        return self.mgr.transmitAPDU(apdu)

    def secureAPDU(self, apdu):
        apdu_dec = binascii.unhexlify(apdu)

        if self.SL == '01' or self.SL == '03':
            # CLA | 0x04
            cla = ord(apdu_dec[0])
            cla |= 0x04

            # LC + 0x08
            lc = ord(apdu_dec[4])
            lc += 0x08

            apdu_dec_sm = struct.pack('B', cla) + apdu_dec[1:4] + struct.pack('B', lc) + apdu_dec[5:]
            apdu_sm = binascii.hexlify(apdu_dec_sm)

            # ICV
            icv = DES_ECB_ENC(self.S_MAC[:16], self.hostMAC)

            # Padding 800000...
            apdu1 = PADDING80(apdu_sm, DES_BLOCK_SIZE)

            # C-MAC
            self.hostMAC = DES_3DES_CBC_MAC(self.S_MAC, icv, apdu1)

            apdu_str = ''

            # encrypt data field
            if self.SL == '03' and ord(apdu_dec[4]) > self.CMAC_LEN:
                di = PADDING80(apdu_sm[10:], DES_BLOCK_SIZE)
                iv = '0000000000000000'
                do = DES3_CBC_ENC(self.S_ENC, iv, di)
                apdu_str += (apdu_sm[:8] + '%02X' % (len(do)/2 + self.CMAC_LEN) + do)
            else:
                apdu_str += apdu_sm

            apdu_str += self.hostMAC

            return self.mgr.transmitAPDU(apdu_str)
        else:
            if apdu_dec[4] == '\x00':
                apdu_cmd = apdu[:-2]
            else:
                apdu_cmd = apdu

            return self.mgr.transmitAPDU(apdu_cmd)

    def select(self, aid):
        self.log('------------------------------SELECT----------------------------')
        SEL_SSD = '00A40400' + ('%02X' % (len(aid)/2)) + aid

        self.mgr.transmitAPDU(SEL_SSD)

    def getSessionKeySet(self):
        return (self.S_ENC, self.S_MAC, self.DEK)
        
    def openSecureChannel(self, SD_AID, hostChallenge=None):

        self.select(SD_AID)

        if hostChallenge is None:
            hostChallenge = '1111111122222222'

        self._initialUpdate(hostChallenge)

        self.S_ENC, self.S_MAC, self.DEK = self._diversifyKey(self.KMC, self.keyDivers, self.sequenceCounter, self.CPG, self.SCP, self.SCP_i)

        self.log('------------------------------Ext Auth--------------------------')

        hostCryptogramDivers = PADDING80(self.sequenceCounter + self.cardChallenge + hostChallenge, DES_BLOCK_SIZE)


        self.log('Host Cryptogram Di:\n\t' + hostCryptogramDivers)
        self.log('S-ENC:\n\t' + self.S_ENC)

        hostCryptogram = DES3_CBC_ENC(self.S_ENC, '00' * DES_BLOCK_SIZE, hostCryptogramDivers)

        hostCryptogram = hostCryptogram[-16:]

        self.log('Host Crytogram:\n\t' + hostCryptogram)

        APDU_AUTHD = '8482' + self.SL + '0010' + hostCryptogram

        apdu1 = PADDING80(APDU_AUTHD, DES_BLOCK_SIZE)

        self.hostMAC = DES_3DES_CBC_MAC(self.S_MAC, '00' * 8, apdu1)

        resp = self.mgr.transmitAPDU(APDU_AUTHD + self.hostMAC)

        return resp[0]
