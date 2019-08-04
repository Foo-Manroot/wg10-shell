#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Diverse utils for the Smartcard assignment.

Foo-Manroot - 2019

Contributors:
    MaxPowell
    j0sNET


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from crypto import wg10
from scard.commands import SmartCardCommands

from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest

import sys
from tqdm import tqdm # To print the progress bar

from smartcard.util import toHexString
NO_COLOR = "\x1b[0m"
LT_RED = "\x1b[1;31m"
LT_BLUE = "\x1b[1;34m"
LT_CYAN = "\x1b[1;36m"
LT_GREEN = "\x1b[1;32m"
LT_YELLOW = "\x1b[1;33m"

END_COLOR = NO_COLOR
OK_COLOR = LT_GREEN
CMD_COLOR = LT_BLUE
ERROR_COLOR = LT_RED
INFO_COLOR = LT_CYAN
WARN_COLOR = LT_YELLOW


class SCardObserver (CardConnectionObserver):
    """
    Little interpreter for the SmartCard events.

    Modified version of
    https://pyscard.sourceforge.io/pyscard-framework.html#a-simple-apdu-tracer-and-interpreter
    """

    def __init__ (self, verbosity = 0):
        self.verbosity = verbosity

    def update (self, cardconnection, ccevent):

        if self.verbosity < 1:
            return


        if ccevent.type == "connect":
            print (INFO_COLOR
                , "Connected to "
                , cardconnection.getReader ()
                , END_COLOR
            )

        elif ccevent.type == "command":

            str = toHexString (ccevent.args [0])
            print ('> ', str)

        elif ccevent.type == "response":

            if [] == ccevent.args[0]:
                print ('< []'
                    , INFO_COLOR
                    , "%02X %02X" % tuple (ccevent.args [-2:])
                    , END_COLOR
                )
            else:
                print ('<'
                    , OK_COLOR
                    , toHexString (ccevent.args [0])
                    , INFO_COLOR
                    , "%02X %02X" % tuple (ccevent.args [-2:])
                    , END_COLOR
                )



class Sender ():

    def __init__ (self):
        self.cmd = SmartCardCommands.INTERNAL_AUTHN ([0, 1, 2, 3, 4, 5, 6, 7])


    def authN (self):
        sc_reader.connection.transmit (self.cmd)


    def read_nt (self):
        int_authn = SmartCardCommands.INTERNAL_AUTHN ([ 0, 1, 2, 3, 4, 5, 6 , 7 ])
        recv = sc_reader.connection.transmit (int_authn)

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if recv [1] != 0x61:
            print ("ERROR: Expected response 0x61; but received '{:s}' instead".format (
                    hex (recv [1])
                )
            )
            return None

        recv = sc_reader.connection.transmit (SmartCardCommands.GET_RESPONSE (recv [2]))
        nt = int.from_bytes (recv [0][:2], byteorder = "big")
        print ("Current NT: {:d} ({:s})".format (nt, hex (nt)))
        return nt


if __name__ == "__main__":

    print ("Trying to connect...")
    verbosity = 0

    # Connection
    try:
        cardtype = AnyCardType ()
        cardrequest = CardRequest (timeout = 10, cardType = cardtype)
        cardservice = cardrequest.waitforcard ()
        observer = SCardObserver (verbosity)

        # self.observer has been initialized when calling 'init ()'
        cardservice.connection.addObserver (observer)

        cardservice.connection.connect ()
        sc_reader = cardservice
        print ("Connected :)")

    except Exception as e:
        print ("ERROR: " + str (e))
        sys.exit (1)

    setup = "from __main__ import s"
    s = Sender ()

    # Reads the current value of "NT"
    initial_nt = s.read_nt ()

    for nt in tqdm (range (initial_nt, 0xFFFF, 2)):
        try:
            s.authN ()
        except KeyboardInterrupt:
            print ("Disconnecting from card...")
            cardservice.connection.disconnect ()
            print ("Done")
            break
