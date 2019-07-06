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
import timeit

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

    def update (self, cardconnection, ccevent):


#        return


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
        """TODO: Docstring for __init__ .

        :f: TODO
        :returns: TODO

        """
        self.cmd = SmartCardCommands.INTERNAL_AUTHN ([0, 1, 2, 3, 4, 5, 6, 7])


    def send (self):
        """TODO: Docstring for send .

        :f: TODO
        :returns: TODO

        """
        sc_reader.connection.transmit (self.cmd)


if __name__ == "__main__":

    print ("Trying to connect...")

    # Connection
    try:
        cardtype = AnyCardType ()
        cardrequest = CardRequest (timeout = 10, cardType = cardtype)
        cardservice = cardrequest.waitforcard ()
        observer = SCardObserver ()

        # self.observer has been initialized when calling 'init ()'
        cardservice.connection.addObserver (observer)

        cardservice.connection.connect ()
        sc_reader = cardservice
        print ("Connected :)")

    except Exception as e:
        print ("ERROR: " + str (e))
        sys.exit (1)

    # Send 3000 commands (3 x 1000 repetitions) and measures time
    times = 23
#    times = 1000

    setup = "from __main__ import s"
    s = Sender ()
    print ("Starting benchmark with {:d} iterations...".format (times))
    print ("Benchmark result: " + str (timeit.repeat ("s.send ()", setup = setup, number = times)) )

