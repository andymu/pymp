#-------------------------------------------------------------------------------
# Name:        mpscard.py
# Purpose: to provide smart card reader management and apdu exchange
#
# Author:      Mu Hongyu
#
# Created:     31-10-2012
# Copyright:   (c) hmu 2012
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import smartcard.util

from smartcard.scard import *

################################################################################
## Smart Card Mangement: Rreader Management, Smart Card APDU level management
################################################################################
class SCManager():

    def __init__(self, LOG_SCREEN=True, LOG_FILE=None, HALT_ON_ERROR=True):
        self.context = None
        self.card = None
        self.protocol = None
        self.reader = None
        self.isRdrConnected = False
        self.logger = LOG_FILE
        self.printScreen = LOG_SCREEN
        self.haltUponException = HALT_ON_ERROR

    def log(self, msg):
        if self.printScreen:
            print msg
        if self.logger is not None:
            self.logger.write(msg + '\n')
    def getCtx(self):
        return self.context

    def getCard(self):
        return self.card

    def getProtocol(self):
        return self.protocol

    def getReader(self):
        return self.reader

    def isRdrOpened(self):
        return self.isRdrConnected

    def getHaltMode(self):
        return self.haltUponException

    def setHaltMode(self, ERR_HALT=True):
        self.haltUponException = ERR_HALT

    def setLogScreen(self, LOG_SCREEN=True):
        self.printScreen = LOG_SCREEN

    def establishCtx(self):

        try:
            res, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
            if res != SCARD_S_SUCCESS:
                raise Exception('Failed to establish context : ' + SCardGetErrorMessage(res))
            self.log('[SCard] => ' + 'SCardContext established!')

        except Exception, message:
            print "Exception:", message
            if self.haltUponException:
                exit()

        self.context = ctx
        return ctx

    def releaseCtx(self):

        try:
            ctx = self.context

            # if reader is not disconnected, disconnected it first
            if self.card is not None:
                self.closeReader(self.card)

            res = SCardReleaseContext(ctx)
            if res != SCARD_S_SUCCESS:
                self.context = None
                raise Exception('Failed to release context: ' + SCardGetErrorMessage(res))

            self.log('[SCard] => ' + 'SCardContext released!')

        except Exception, message:
            print "Exception:", message
            if self.haltUponException:
                exit()

    def listReader(self, ctx=None):

        rdrs = []
        try:
            if ctx is None:
                ctx = self.context

            res, rdrs = SCardListReaders(ctx, [])
            if res != SCARD_S_SUCCESS:
                raise Exception('Failed to list readers: ' + SCardGetErrorMessage(res))

            if len(rdrs) < 1:
                raise Exception('No smart card reader found')

            self.reader = rdrs[0]

        except Exception, message:
            print "Exception:", message
            if self.haltUponException:
                exit()

        return rdrs

    def openReader(self, rdr=None):

        try:
            if rdr is None:
                rdr = self.reader

            self.log('[SCard] => ' + 'SCardConnect { ' + rdr + ' } ...')

            res, crd, ptl = SCardConnect(self.context, rdr,
                SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
            if res != SCARD_S_SUCCESS:
                raise Exception('Unable to connect: ' + SCardGetErrorMessage(res))
            self.log('[SCard] => { '+ rdr + ' } connected [ T' + str(ptl) + ' ]!')

        except Exception, message:
            print "Exception:", message
            if self.haltUponException:
                exit()

        self.card = crd
        self.protocol = ptl
        self.isRdrConnected = True

        return (crd, ptl)

    def closeReader(self):

        try:
            res = SCardDisconnect(self.card, SCARD_UNPOWER_CARD)
            if res != SCARD_S_SUCCESS:
                raise Exception('Disconnect failed= ' + SCardGetErrorMessage(res))

            self.isRdrConnected = False
            self.card = None

            self.log('\n[SCard] => SCardDisconnect { ' + self.reader + ' } disconnected!')

        except Exception, message:
            print 'Exception:', message
            if self.haltUponException:
                exit()

    def getATR(self, crd=None):
        if crd is None:
            hresult, reader, state, protocol, atr = SCardStatus(self.card)
        else:
            hresult, reader, state, protocol, atr = SCardStatus(crd)

        return smartcard.util.toHexString(atr)

    def transmitAPDU(self, cmd, crd=None, ptl=None):
        '''
            cmd = '00A4040008A000000003000000'
            spaces are allowed
        '''

        resp_str = None

        try:
            
            if crd is None:
                crd = self.card
            if ptl is None:
                ptl = self.protocol

            self.log('[APDU ] => ' + cmd.upper())

            cmd_lst = smartcard.util.toBytes(cmd)

            res, resp = SCardTransmit(crd, ptl, cmd_lst)
            if res != SCARD_S_SUCCESS:
                print 'SCardTransmit=', res, hex(res)
                raise Exception('SCardTransmit failed: ' + SCardGetErrorMessage(res))

            if len(resp) < 2:
                raise Exception('SCardTransmit failed: len of response < 2')

            # SW = 61xx or 6Cxx
            if resp[-2] == 0x61:
                get_resp_cmd = [0x00, 0xC0, 0x00, 0x00, resp[1]]
                res, resp = SCardTransmit(crd, ptl, get_resp_cmd)
                if res != SCARD_S_SUCCESS:                    
                    raise Exception('Get Response failed: ' + SCardGetErrorMessage(res))
            if resp[-2] == 0x6C:
                cmd_lst.append(resp[1])
                res, resp = SCardTransmit(crd, ptl, cmd_lst)
                if res != SCARD_S_SUCCESS:
                    raise Exception('APDU with given len resending failed:' + SCardGetErrorMessage(res))

            self.log('[APDU ] <= ' + smartcard.util.toHexString(resp, smartcard.util.PACK))

            resp_str = smartcard.util.toHexString(resp, smartcard.util.PACK)

            sw = int(resp_str[-4:], 16)

            if resp[-2] != 0x90 and resp[-2] != 0x62 and resp[-2] != 0x63:
                raise Exception('[APDU ] <=: SW=' + resp_str[-4:])

        except Exception, message:
            print 'Exception:', message

            if self.haltUponException:
                self.closeReader()
                self.releaseCtx()
                exit()

        return  (resp_str[:-4], sw)

def main():

    logger = open('hello.log', 'a+')

    sc = SCManager(loggerHandle=logger)

    sc.establishCtx()
    rdrs = sc.listReader()
    print rdrs

    sc.openReader()


    sc.transmitAPDU('00A4040008A000000003000000')

    sc.closeReader()

    sc.releaseCtx()

    logger.close()

if __name__ == '__main__':
    main()
