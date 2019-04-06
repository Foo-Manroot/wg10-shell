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

import binascii
import pyDes
import cmd
import re

from enum import Enum
from binascii import unhexlify as unhex
from binascii import hexlify as hex2

# Smartcard automatic interaction
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
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



class SmartCardCommands (Enum):
    """
    Collection of lambda functions to build the proper messages
    """
    GET_RESPONSE = lambda length: [ 0, 0xc0, 0, 0, length ]
    INTERNAL_AUTHN = lambda challenge, level: [ 0x00, 0x88, 0x00, level, 0x08 ] + challenge
    SELECT_NAME = lambda name_hex: [ 0x00, 0xa4, 0x04, 0x00, len (name_hex) ] + name_hex
    SELECT_ID = lambda ident: [ 0x00, 0xa4, 0x02, 0x00, len (ident) ] + ident
    READ_BINARY = lambda le, offset, ef_id: [ 0x00, 0xB0, ef_id, offset, le ]
    VERIFY_SECRET_CODE = lambda secret_code: [ 0x00, 0x20, 0x00, 0x00, 0x08 ] + secret_code




class SmartCardObserver (CardConnectionObserver):
    """
    Little interpreter for the SmartCard events.

    Modified version of
    https://pyscard.sourceforge.io/pyscard-framework.html#a-simple-apdu-tracer-and-interpreter
    """

    def update (self, cardconnection, ccevent):

        if ccevent.type == "connect":
            print (INFO_COLOR + "Connected to " + cardconnection.getReader () + END_COLOR)

        elif ccevent.type == "command":

            str = toHexString (ccevent.args [0])
            print ('> ', str)

        elif ccevent.type == "response":

            if [] == ccevent.args[0]:
                print ('< []', INFO_COLOR, "%02X %02X" % tuple (ccevent.args [-2:]), END_COLOR)
            else:
                print ('<', OK_COLOR, toHexString (ccevent.args [0]), INFO_COLOR,
                    "%02X %02X" % tuple (ccevent.args [-2:]), END_COLOR
                )




class Crypto ():
    """
    Global variables:

        MASTER_KEY (16 B): raw bytes -> The master key used to derive session keys
        self.NT (2 B): int -> Current value of the NT counter

        self.TK (16 B): int -> Temporal Key
        self.SK (16 B): int -> Session Key
    """

    def __init__ (self, master = "MASTERADMKEY_002".encode ("utf-8")):
        """
        Initialization of the object

        @param master
                Master key used to derive the rest of the keys
        """
        self.MASTER_KEY = master
        self.NT = None
        self.SK = None
        self.TK = None



    def derive_temp_key (self, nt):
        """
        Derives the session key.

        @param nt: int
            Current value of the counter

        @return: boolean
            True if the process completed correctly
            False if there has been any error
        """

        # We avoid changing the state of the object until the end
        local_nt = nt + 1

        #         (2 B)
        # 00 00 00 NT 00 00 00  -> 8 Bytes
        data = binascii.unhexlify (
            "000000" + hex (local_nt)[2:].zfill (4) + "000000"
        )

        # 3DES (MK1 || MK2, data)
        deskey = self.MASTER_KEY
        TK1 = pyDes.triple_des (deskey).encrypt (data)

        # 3DES (MK2 || MK1, data)
        deskey = self.MASTER_KEY [8:] + self.MASTER_KEY [:8]
        TK2 = pyDes.triple_des (deskey).encrypt (data)

        self.TK = TK1 + TK2
        return True





    def derive_session_key (self, nt):
        """
        Derives the session key.


        @param nt: int
            Current value of the counter


        @return: boolean
            True if the process completed correctly
            False if there has been any error
        """

        # We first have to derive the temporal key
        if not self.derive_temp_key (nt):
            print ("ERROR: Couldn't derive temporal key")
            return False

        # We avoid changing the state of the object until the end
        local_nt = nt + 2

        #         (2 B)
        # 00 00 00 NT 00 00 00  -> 8 Bytes
        data = binascii.unhexlify (
            "000000" + hex (local_nt)[2:].zfill (4) + "000000"
        )

        # 3DES (MK1 || MK2, data)
        deskey = self.MASTER_KEY
        SK1 = pyDes.triple_des (deskey).encrypt (data)

        # 3DES (MK2 || MK1, data)
        deskey = self.MASTER_KEY [8:] + self.MASTER_KEY [:8]
        SK2 = pyDes.triple_des (deskey).encrypt (data)

        self.SK = SK1 + SK2

        return True






    def verify_internal_authN (self, msg, rand):
        """
        Virifies the response received from the Internal AuthN command.
        In the process, it updates the value of self.NT, self.TK and self.SK.

        @param msg: hex string
                Response message from the SmartCard.
                Its length must be 10 Bytes (20 hex characters)

        @param rand: hex string
                Random number sent to the SmartCard

        @return: int
            -3 the verification failed
            -2 error calculating the keys
            -1 the length of the msg or rand parameters was incorrect
            0 if the operation finished without any warning
            > 1, indicating the number of non-critical warnings
        """
        ret_val = 0
        # We're going to work with binary from now on
        msg = binascii.unhexlify (msg)
        rand = binascii.unhexlify (rand)

        # The message has to be 10 Bytes long
        # The random number, 8 Bytes
        if (len (msg) != 10) or (len (rand) != 8):
            print ("ERROR: Either the message '{:s}' or the random number '{:s}' don't "
                    "have the correct length.".format (
                        binascii.hexlify (msg).decode ("utf-8")
                        , binascii.hexlify (rand).decode ("utf-8")
                    )
            )
            return -1

        nt = int.from_bytes (msg [:2], byteorder = "big")
        signature = msg [2:]
        # If available, checks the NT counter
        if not self.NT:
            self.NT = (nt - 2)

        if self.NT != (nt - 2):
            print ("WARNING: the received value of NT '{:d}' doesn't match with "
                    "the predicted one '{:d}'".format (nt, self.NT + 2)
            )
            ret_val = ret_val + 1

        # Calculates the Session Key
        # It may fail for multiple reasons, so it's wise to do it before making further
        # changes in the internal state of the object

        if not self.derive_session_key (self.NT):
            print ("ERROR: Couldn't derive session key")
            return -1

        # ----------
        # Keys derived and all checks done -> starts the verification


        print ("Derived keys:\n\tTemporal -> {:s}\n\tSession ->  {:s}".format (
                binascii.hexlify (self.TK).decode ("utf-8")
                , binascii.hexlify (self.SK).decode ("utf-8")
            )
        )

        # 3DES (TK, rand) == msg
        calc_signature = pyDes.triple_des (self.TK).encrypt (rand)

        if calc_signature != signature:
            print ("ERROR: Verification failed. Should be '{:s}', "
                "but was '{:s}'".format (
                    binascii.hexlify (calc_signature).decode ("utf-8")
                    , binascii.hexlify (signature).decode ("utf-8")
                )
            )
            ret_val = -3
#            return -3

        # ---------------
        # Everything finished -> the state can be changed
        self.NT = self.NT + 2

        return ret_val





    def gen_internal_authN (self, nt, random):
        """
        Simulates the operations of the Smartcard to derive the temporal and session
        keys and returns the signature that should be read from the card.


        Modifies the state of the object:
            self.NT is set to (nt + 2) after the process is done


        @param nt: int
            Current value of the counter

        @param random: raw bytes
                Random number sent to the SmartCard


        @return: raw bytes
            The signature that corresponds to the returned message
        """
        # The random number has to be 8 Bytes long
        if len (random) != 8:
            print ("ERROR: The random number '{:s}' doesn't "
                    "have the correct length (8 Bytes).".format (
                        hex2 (random).decode ("utf-8")
                    )
            )
            return None


        if not self.derive_session_key (nt = nt):
            print ("ERROR: Couldn't derive session key")
            return None

#        print ("Derived keys:\n\tTemporal -> {:s}\n\tSession ->  {:s}".format (
#                binascii.hexlify (self.TK).decode ("utf-8")
#                , binascii.hexlify (self.SK).decode ("utf-8")
#            )
#        )

        calc_signature = pyDes.triple_des (self.TK).encrypt (random)
        # ---------------
        # Everything finished -> the state can be changed
        self.NT = (nt + 2)

        return calc_signature



    def encrypt (self, command):
        """
        Encrypts the data (not the header of the command) and signs it.

        @param data: raw bytes
            Data to encrypt and sign.

        @return: raw bytes
            Raw bytes of the data encrypted and signed
            , or None if there was an error
        """

        # The parameter 'command' is 5 Bytes length, plus all the data that has to be
        # signed
        if len (command) < 5:
            print (ERROR_COLOR
                + "ERROR: the command needs to be at least 5 Bytes long"
                + END_COLOR
            )
            return None

        data = command [5:]

        signature = self.sign (command)[-3:]

        if not signature and len (signature) != 8:
            return None

        encrypted = b''
        if data:
            encrypted = pyDes.triple_des (self.SK
                                    , IV = b'\x00' * 8
                                    , mode = pyDes.CBC
                                    , pad = '\x00'
                    ).encrypt (data)

        print ("Data:      '{:s}'".format (hex2 (data).decode ("utf-8")))
        print ("Encrypted: '{:s}'".format (hex2 (encrypted).decode ("utf-8")))
        print ("Signature: '{:s}'".format (hex2 (signature).decode ("utf-8")))


        # Header + encrypted data +
        return command [:5] + encrypted + signature






    def sign (self, data):
        """
        Calculates the signature of the provided data.
        This function has to be called AFTER having calculated the session key using
        verify_internal_authN ().

        This function generates 8 Bytes; but the signature to be added are only the three
        Least Significant Bytes

        @param data: raw bytes
            Bytes to sign

        @return: array | None
            The full signature of the provided data (remember to get only the 3 LSB), as
                raw bytes,
            or None if the signing failed (most probably because the session key hasn't
                been calculated yet -> verify_internal_authN() is needed first)
        """
        if not self.SK:
            print (ERROR_COLOR + "ERROR: The session key hasn't been initialized. "
                    + "Please call " + CMD_COLOR + "verify_internal_authN ()"
                    + ERROR_COLOR + "first" + END_COLOR
            )
            return None

        # For all the blocks from 0 to N-1
        # DES CBC with the key SK1 and IV = 0000...
        prev_block = b"\x00" * 8
        signature = None

        for i in range (0, len (data), 8):

            current_block = data [i:i+8]

            size = len (current_block)
            # Pad with 0's if necessary
            if size < 8:
                current_block = bytes (current_block) + b"\x00" * (8 - size)

            current_block = [ (current_block [j] ^ prev_block [j]) for j in range (8) ]

            if i < (len (data) - 8):
                prev_block = pyDes.des (self.SK [:8]).encrypt (current_block)
            else:
                signature = pyDes.triple_des (self.SK).encrypt (current_block)

        return signature





    def verify_signature (self, data):
        """
        Verifies the signature of the data by calculating it and seing if they match.


        @param data: raw bytes
            Bytes received from the SC, including the 3-Bytes signature

        @return: boolean
            True if the signature matched,
            False otherwise
        """
        # The signature is just the 3 LSB -> Generates signature and verify Bytes 6, 7,
        # and 8
        calc_sign = self.sign (data [:-3])
        recv_sign = data [:-3]

        return calc_sign == recv_sign





#### CMD-related functions

class Shell (cmd.Cmd):
    """Class to interpret the input and execute the proper Crypto method"""


    def init (self):
        """
        Initializes all the internal elements.
        """
        self.do_init (None)
        self.crypto.NT = 0
        self.sc_reader = None
        self.observer = SmartCardObserver ()
        self.selected_dir = None
        self.selected_file = None


    def do_get_status (self, args):
        """
        Prints the current status of the object (NT, master key...)
        """
        msg = "This value hasn't been initialized"
        print ("NT (counter) = "
                + (hex (self.crypto.NT) if self.crypto.NT else msg)
        )
        print ("Session Key =  "
                + (hex2 (self.crypto.SK).decode ("utf-8")
                    if self.crypto.SK else msg
                )
        )
        print ("Temporal Key = "
                + (hex2 (self.crypto.TK).decode ("utf-8")
                    if self.crypto.TK else msg
                )
        )
        print ("Master Key =   "
                + (hex2 (self.crypto.MASTER_KEY).decode ("utf-8")
                    if self.crypto.MASTER_KEY else msg
                )
        )
        print ("---------------------")
        print (
            ("Connected with " + self.sc_reader.connection.getReader ())
            if self.sc_reader else
            "Not connected to any reader"
        )
        print ("Currently selected directory (MF or DF): {:s}".format (
            self.selected_dir if self.selected_dir else " - ")
        )
        print ("Currently selected file (EF): {:s}".format (
            self.selected_file if self.selected_file else " - ")
        )



    # -----------------------------------------------


    def do_EOF (self, args):
        """
        Press EOF (^D) to exit the shell. Calls do_quit ()
        """
        return self.do_quit (args)


    def do_quit (self, args):
        """
        Exits the shell.
        """
        if self.sc_reader:
            print ("Disconnecting the reader...")
            self.sc_reader.connection.disconnect ()

        print ("Bye :)")
        return True




    def do_init (self, args):
        """
        Initializes a Crypto object with the defined master key.

        SYNOPSIS
            init [OPTION]...

        DESCRIPTION
            -l  [HEX_VALUE] This option is only used when you're going to
                            do a "LOCAL" Internal Authenticate.

        @param master_key: hex string or int number (optional)
            - Hexadecimal string with the master key used to derive the keys
            - Integer number of your card
        """
        if args:
            try:
                binary_key_str = None

                if ("-l" in args):
                    binary_key_str = unhex(args.split(" ")[1])
                elif args.isdigit():
                    binary_key_str = ("MASTERADMKEY_" + args.zfill(3)).encode("utf-8")
                else:
                    binary_key_str = unhex (args)

                self.crypto = Crypto (binary_key_str)

            except Exception as e:
                print (ERROR_COLOR
                    + "ERROR: Couldn't initialize the object -> " + str (e)
                    + END_COLOR
                )
                return None

        else:
            self.crypto = Crypto ()

        print ("Object correctly initialized with master key: 0x{:s}".format (
                hex2 (self.crypto.MASTER_KEY).decode ("utf-8")
            )
        )

    ### Low Level functions

    def do_ll_internal_authN (self, args):
        """
        LOW LEVEL function

        Simulates the internal authentication process done by the smartcard to derive the
        session key.
        !!!!!!!!!!!!!
        BE AWARE that, after requesting the card an authentication response, the returned
        data is the initial NT + 2.
        So, in order to get the same response that the card generated, you should set
        this NT to (whatever-the-card-returned minus 2)


        @param nt: hex string (2 Bytes)
                The current value of the counter (the value returned by the previous
            internal_authN call).


        @param random: hex string (8 Bytes)
                The challenge to send to the smartcard
        """
        if not args or (len (args.split (" ")) != 2):
            print ("Not enough arguments. Execute 'help next_internal_authN' for "
                + "more info.")
            return None

        try:
            s = args.split (" ")
            nt = int.from_bytes (unhex (s [0]), byteorder = "big")
            random = unhex (s [1])

            ret_val = self.crypto.gen_internal_authN (nt, random)
            if ret_val:
                print ("Response from the smartcard: {:s}".format (
                        hex2 (ret_val).decode ("utf-8")
                    )
                )
            else:
                print ("ERROR: Couldn't generate the internal authN")

        except Exception as e:
            print ("ERROR: Couldn't calculate the internal authN -> " + str (e))
            return None


    def do_ll_next_internal_authN (self, args):
        """
        LOW LEVEL function

        Simulates the internal authentication process done by the smartcard to derive the
        session key.

        @param random: hex string (8 Bytes)
                The challenge to send to the smartcard
        """
        if not args:
            print ("Not enough arguments. Execute 'help internal_authN' for more info.")
            return None

        try:
            random = unhex (args)

            ret_val = self.crypto.gen_internal_authN (self.crypto.NT, random)
            if ret_val:
                print ("Response from the smartcard: {:s}".format (
                        hex2 (ret_val).decode ("utf-8")
                    )
                )
            else:
                print ("ERROR: Couldn't generate the internal authN")

        except Exception as e:
            print ("ERROR: Couldn't calculate the internal authN -> " + str (e))
            return None



    def do_ll_sign (self, args):
        """
        LOW LEVEL function

        Signs the given command and returns it with its signature (only the three Least
        Significant Bytes) appended.

        @params data: hex string
            The data to sign
        """
        if not args:
            print ("Not enough arguments. Execute 'help sign' for more info.")
            return None

        try:
            data = unhex (args)

            ret_val = self.crypto.sign (data)
            if ret_val:
                print (hex2 (ret_val))
                print (hex2 (data + ret_val [-3:]).decode ("utf-8"))
            else:
                print ("ERROR: Couldn't sign the data")

        except Exception as e:
            print ("ERROR: Couldn't sign data -> " + str (e))
            return None





    def do_ll_set_nt (self, args):
        """
        LOW LEVEL function

        Sets the value of NT.
        !!!!!!!!!!!!!
        BE AWARE that, after requesting the card an authentication response, the returned
        data is the initial NT + 2.
        So, in order to get the same response that the card generated, you should set
        this NT to (whatever-the-card-returned minus 2)

        @param nt: hex string
            New value of the counter
        """
        if not args:
            print ("Not enough arguments. Execute 'help set_nt' for more info.")
            return None

        try:
            bin_nt = unhex (args)
            self.crypto.NT = int.from_bytes (bin_nt, byteorder = 'big')

        except Exception as e:
            print ("ERROR: " + str (e))
            return None




    def do_ll_encrypt_command (self, args):
        """
        LOW LEVEL function

        Encrypts the given command and returns its data encrypted with its signature.

        @param command: hex string
            Command to encrypt and sign
        """
        if not args:
            print ("Not enough arguments. Execute 'help encrypt_command' for more info.")
            return None

        try:
            encrypted = self.crypto.encrypt (unhex (args))
            if encrypted:
#                print ("\nSending the command to sc...\n")
#                self.do_send_raw (hex2 (encrypted).decode("utf-8"))
                print (binascii.hexlify (encrypted))
            else:
                print (ERROR_COLOR + "Error encrypting command" + END_COLOR)

        except Exception as e:
            print (ERROR_COLOR + "ERROR: " + str (e) + END_COLOR)
            return None




    #### Automatic connection with the SC

    def do_connect (self, args):
        """
        Waits until a smartcard is present and initializes everything that's needed.
        """
        print ("Trying to connect...")

        try:
            cardtype = AnyCardType ()
            cardrequest = CardRequest (timeout = 10, cardType = cardtype)
            cardservice = cardrequest.waitforcard ()

            # self.observer has been initialized when calling 'init ()'
            cardservice.connection.addObserver (self.observer)

            cardservice.connection.connect ()
            self.sc_reader = cardservice

        except Exception as e:
            print ("ERROR: " + str (e))
            return None





    def do_disconnect (self, args):
        """
        Disconnects the connection with the reader (if any)
        """

        try:
            if not self.sc_reader:
                print ("No connection available")

            else:
                self.sc_reader.connection.disconnect ()
                self.sc_reader = None
                print ("Disconnected")

        except Exception as e:
            print ("ERROR: " + str (e))
            return None



    def do_find_my_sc(self, args):
        """
        Try to find the number of your smartcard.
        """
        respond = self.get_session_key_from_sc()
        if respond is None:
            return None

        # Search for the MK by comparing it to the signature
        # of the random data sent it from the smartcard
        possible_key = []
        for x in range(1,100):
            self.crypto.MASTER_KEY = ("MASTERADMKEY_"
                + str(x).zfill(3)).encode ("utf-8")

            # NT = respond[0] - 2
            calc_signature = self.crypto.gen_internal_authN (respond[0] - 2,
                 bytes.fromhex("0001020304050607"))
            if calc_signature == respond[1]:
                possible_key.append(self.crypto.MASTER_KEY.decode ("utf-8"))

        if not possible_key:
            print (INFO_COLOR
                + "I'm afraid that's impossible to find your card number,"
                + "you'd better ask the professor :P"
                + END_COLOR
            )
        else:
            print ("\nThese are your possible keys:\n")
            for index in range(len(possible_key)):
                print ("{:d}. {:s}".format (
                        index + 1,
                        possible_key[index]
                    )
                )
            print (INFO_COLOR
                + "\nNEXT: type the [init command] with one of the MKs listed above.\n"
                + END_COLOR
            )



    def send (self, cmd):
        """
        Sends the given command (an int array) to the reader and returns the response
        (not to be confused with the result of GET_RESPONSE).


        @param command: int array
            Information to send to the SmartCard


        @return: (int array, int, int) | None
            A tuple with the following elements
                - data (an int array)
                - SW1
                - SW2
            , or (None, None, None), if there has been an error
        """
        if not self.sc_reader:
            print (ERROR_COLOR
                + "No connection to the reader. Please, use the command "
                + CMD_COLOR + "'connect'" + END_COLOR
            )
            return (None, None, None)

        else:
            try:
                return self.sc_reader.connection.transmit (cmd)

            except Exception as e:
                print (ERROR_COLOR + "ERROR: " + str (e) + END_COLOR)
                return (None, None, None)



    def do_internal_authN (self, args):
        """
        Sends an 'internal authenticate' command to the smartcard with a super 'random'
        number: 0x0001020304050607

        The smartcard has to be connected first

        If you specify the '-l' flag, the command sent will be INTERNAL
        """
        # We could generate a random number; but we don't really care about it right now
        if("-l" in args):
            cmd = SmartCardCommands.INTERNAL_AUTHN_LOCAL ([0, 1, 2, 3, 4, 5, 6, 7])
        else:
            cmd = SmartCardCommands.INTERNAL_AUTHN ([0, 1, 2, 3, 4, 5, 6, 7])
        recv = self.send (cmd)

        if not recv:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if recv [1] != 0x61:
            print ("ERROR: Expected response 0x61; but received '{:s}' instead".format (
                    hex (recv [1])
                )
            )
            return None

        print ("==> Internal authentication completed. Verifying response")

        # Gets the response with the new NT and the signature to verify it
        cmd = SmartCardCommands.GET_RESPONSE (recv [2])
        recv = self.send (cmd)

        if not recv:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
        if recv [1] != 0x90 or recv [2] != 0x00:
            print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' instead"
                    .format (hex (recv [1]), hex (recv [2]))
            )
            return None

        recv = "".join ([ hex (x)[2:].zfill (2) for x in recv [0] ])

        if self.crypto.verify_internal_authN (recv, "0001020304050607") == 0:
            print ("Signature correct")
        else:
            print ("WARNING: Wrong signature")



    def get_session_key_from_sc(self, challenge = [0, 1, 2, 3, 4, 5, 6, 7], level = 0x00):
        """
        Sets a valid session key for the current DF via "Internal Authenticate" command.

        @param challenge: int array
            8-byte random data

        @param level: hex
            A global level is used to calculate a SK with the MF data.
            - global  0x00 (by default)
            - local   0x80

        @return: (int, int) | None
            A tuple with the following elements:
            - The 2 first bytes is the current NT in the card
            - The 8 following bytes is the signature of the random data sent
            , or None, if there has been an error.
        """
        # We could generate a random number; but we don't really care about it right now
        cmd = SmartCardCommands.INTERNAL_AUTHN (challenge, level)
        res = self.send (cmd)

        if not res:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if res [1] != 0x61:
            print ("ERROR: Expected response 0x61; but received '{:s}' instead".format (
                    hex (res [1])
                )
            )
            return None

        print ("==> Internal authentication completed. Verifying response...")

        # Gets the response with the new NT and the signature to verify it
        cmd = SmartCardCommands.GET_RESPONSE (res [2])
        res = self.send (cmd)

        if not res:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
        if res [1] != 0x90 or res [2] != 0x00:
            print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' instead"
                    .format (hex (res [1]), hex (res [2]))
            )
            return None

        recv = unhex("".join ([ hex (x)[2:].zfill (2) for x in res [0] ]))

        # We extract the NT and Signature from the card's response
        nt = int.from_bytes (recv [:2], byteorder = "big")
        signature = recv [2:]

        return nt, signature



    def do_send_raw (self, args):
        """
        Sends the raw bytes provided in the input to the reader and prints its response.

        @param bytes
            Hex string (case insensitive and can have whitespaces or not, doesn't matter)
        """
        # We don't care about the format -> remove spaces and group in pairs
        args = args.replace (" ", "")

        if (len (args) % 2) != 0:
            print ("ERROR: Odd-length string")
            return None

        cmd = [ int (args [i:i + 2], 16) for i in range (0, len (args), 2) ]

        recv = self.send (cmd)

        if not recv:
            print ("Couldn't get a response from the SmartCard")

        # Checks if there's a response from the smartcard and consumes it
        try:
            if recv [1] == 0x61:
                cmd = SmartCardCommands.GET_RESPONSE (recv [2])
                self.send (cmd)
        except TypeError as e:
            print (ERROR_COLOR + "ERROR: " + str (e) + END_COLOR)




    def do_send_signed (self, args):
        """
        Sign the (command || data) provided and send it to the sc
        to later verify its response.

        Notice: CLA || INS || P1 || P2 || Lc || DATA (where Lc = len(data) + 3)

        @param bytes
            Hex string (case insensitive and can have whitespaces or not, doesn't matter)
        """
        # We don't care about the format -> remove spaces and group in pairs
        args = args.replace (" ", "")

        if (len (args) % 2) != 0:
            print ("ERROR: Odd-length string")
            return None

        # Secure Messaging Mechanism
        cmd = [ int (args [i:i + 2], 16) for i in range (0, len (args), 2) ]
        calc_signature = list (self.crypto.sign (bytes (cmd)))

        if not calc_signature:
            print ("The signature couldn't be calculated")
            return None

        # Add the 3 least significant bytes to the end of the plain data, and
        # Send the new command
        recv = self.send (cmd + calc_signature [-3:])
        if not recv:
            print ("Couldn't get a response from the SmartCard")

        try:
            # Checks the response of the smartcard with the rest of the signature
            if recv[1] == 0x6A and recv[2] == 0x82:
                print (WARN_COLOR +"\nWARNING: The file is not or cannot be selected. "
                    + "Try to select it with: select_ef [your EF_ID] command.\n" + END_COLOR 
                )
                return None
            
            if recv [1] != 0x61:
                print (WARN_COLOR 
                    + "WARNING: Couldn't verify the signature from the smartcard"
                    + END_COLOR
                )

            else:
                # We verified the 3-bytes of the cryptogram (signature)
                cmd = SmartCardCommands.GET_RESPONSE (recv [2])
                recv_verification = self.send (cmd)

                if (recv_verification
                    and   # 3 most significant bytes
                    (list (calc_signature [:3]) == recv_verification [2])
                ):
                    print (INFO_COLOR 
                        + "\nSignature returned from the smartcard verified!\n" 
                        + END_COLOR
                    )

                else:
                    print ("WARNING: Verification of the signature failed.")
        except TypeError as e:
            print (ERROR_COLOR + "ERROR: " + str (e) + END_COLOR)



    def do_select_dir_by_name (self, args):
        """
        Selects the specified Dedicated File (directory in the filesystem) or Master File
        (root directory) using its name-

        @param bytes
            String (ASCII) with the name of the directory to select
        """
        if not args:
            print ("No name supplied. See 'help select_dir_by_name'")
            return None

        hex_str = hex2 (args.encode ("utf-8"))
        list_name = [ int (hex_str [i : i + 2], 16) for i in range (0, len (hex_str), 2) ]

        cmd = SmartCardCommands.SELECT_NAME (list_name)
        recv = self.send (cmd)
        # Whether the command executed successfully or not, the selection changed
        self.selected_dir = None

        if not recv:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if recv [1] == 0x61:

            cmd = SmartCardCommands.GET_RESPONSE (recv [2])
            recv = self.send (cmd)

            if not recv:
                print ("Couldn't get a response from the SmartCard")
                return None

            # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
            if (recv [1] == 0x90) and (recv [2] == 0x00):

                self.selected_dir = args
                print ("Selected directory '{:s}'".format (args))

            else:
                print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' "
                    "instead".format (hex (recv [1]), hex (recv [2]))
                )
                return None

        else:
            print (WARN_COLOR + "DF or MF not selected" + END_COLOR)



    def do_select_file_by_id (self, args):
        """
        Select the specified Elementary File (file in the filesystem) by its ID

        @param bytes
            Hex string (case insensitive and can have whitespaces or not, doesn't matter)
            with the identifier (HEX ENCODED) of the EF
        """
        if not args:
            print ("No EF supplied. See 'help select_ef'")
            return None

        # We don't care about the format -> remove spaces and group in pairs
        args = args.replace (" ", "")

        if (len (args) % 2) != 0:
            print (ERROR_COLOR + "ERROR: Odd-length string" + END_COLOR)
            return None

        # We could generate a random number; but we don't really care about it right now
        ef_id = [ int (args [i:i + 2], 16) for i in range (0, len (args), 2) ]
        cmd = SmartCardCommands.SELECT_ID (ef_id)
        recv = self.send (cmd)
        # Whether the command executed successfully or not, the selection changed
        self.selected_file = None

        if not recv:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if recv [1] == 0x61:

            cmd = SmartCardCommands.GET_RESPONSE (recv [2])
            recv = self.send (cmd)

            if not recv:
                print ("Couldn't get a response from the SmartCard")
                return None

            # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
            if (recv [1] == 0x90) and (recv [2] == 0x00):

                self.selected_file = args
                print ("Selected EF '{:s}'".format (args))

            else:
                print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' "
                    "instead".format (hex (recv [1]), hex (recv [2]))
                )
                return None

        else:
            # SW1 == 0x6A and SW2 == 0x82 means "file not found"
            if (recv [1] == 0x6A) and (recv [2] == 0x82):

                print ("File not found")
            else:
                print ("EF not selected")



    def do_read_binary (self, args):
        """
        Read the content from a transparent binary file.

        USE: You can use whitespace, comma or a pipe
             to separate the arguments.

        $_$ read_binary [length] [offset] [ef_id]

        @param int array
            [length]    Number of bytes to read.
            [offset]    Offset in bytes from the first byte to read.
            [ef_id]     ID of your EF for "implicit selection".
                        (Skip for direct selection)
        """
        try:
            params = list(map(int, filter(None, re.split('[,| ]', args))))
            p1 = 0

            if len(params) < 2 or len(params) > 3:
                self.do_help("read_binary")
                return None

            if not all(x >= 0 for x in params):
                print ("Warning: all the number must be greater"
                    + "or equal to zero."
                )
                return None

            # To use implicit selection
            if (len(params) == 3
                and (params[2] > 1 and params[2] <= 30)):
                # b8=1, b7=0. b6=0
                # b5...b1 = ef_id = P1
                p1 = int('100{0:05b}'.format(params[2]), 2)

            cmd = SmartCardCommands.READ_BINARY (params[0], params[1], p1)
            self.do_send_raw(cmd)

        except ValueError:
            print ("ERROR: All arguments must be integer type!")



    def do_read_full_binary (self, args):
        """
        Reads the currently selected file, assuming its structure is of a transparent
        (binary) file, and dumps it to stdout either as an HEX ENCODED
        string (by default), or as plain (UTF-8) text, if '-t' is specified.

        -> The file to read has to be selected first

        -> If this command throws an error, check if the selected file is 'transparent'


        @param flag: string
            It can be one of the following values:
                -t: Output is assumed to be plain text, and is decoded using UTF-8
        """
        # First, it figures out the length of the file to read
        cmd = SmartCardCommands.READ_BINARY (0x00)
        recv = self.send (cmd)

        if not recv:
            print ("Couldn't get a response from the SmartCard")
            return None

        # Expected SW1 == 0x6C and SW2 = (bytes to read)
        if recv [1] == 0x6C:

            print ("Reading {:d} bytes from the file".format (recv [2]))
            cmd = SmartCardCommands.READ_BINARY (recv [2])
            recv = self.send (cmd)

            if not recv:
                print ("Couldn't get a response from the SmartCard")
                return None

            # Output dumping
            print ("Contents of the file:")
            print ("---------------------")

            if "-t" in args:

                try:
                    s = "".join ([ chr (x) for x in recv [0] ])
                    print (s)
                except Exception as e:
                    print ("Can't interpret contents as plain text: -> " + str (e))
            else:
                s = bytes (recv [0])
                print (binascii.hexlify (s))
            print ("\n---------------------")

        else:
            print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' "
                "instead".format (hex (recv [1]), hex (recv [2]))
            )



    def do_verify_secret_code(self, args):
        """
        Compare the received "secret code" (from IFD) with the secret code
        previously stored in the sc.

        @param secret_code: hex string
            secret_code to encrypt and then verify it
        """
        if not args:
            print (WARN_COLOR
                + "Not enough arguments. Execute 'help verify_secret_code' for more "
                + "info." + END_COLOR
            )
            return None

        if not self.crypto.SK:
            print (ERROR_COLOR
                + "ERROR: The session key hasn't been initialized. Please call "
                + CMD_COLOR + "internal_auth" + ERROR_COLOR + " first"
                + END_COLOR
            )
            return None

        data = unhex(args)
        encrypted = b''

        try:
            if data:
                encrypted = pyDes.triple_des (self.crypto.SK
                                        , IV = b'\x00' * 8
                                        , mode = pyDes.CBC
                                        , pad = '\x00'
                        ).encrypt (data)

            cmd = SmartCardCommands.VERIFY_SECRET_CODE (hex2(encrypted))
            self.do_send_raw(cmd)
        except Exception as e:
            print (ERROR_COLOR
                + "ERROR: Couldn't verify the secret code -> " + str (e)
                + END_COLOR
            )
            return None



if __name__ == "__main__":

    s = Shell ()
    s.prompt = "\033[93m$_$ \033[00m"
    s.init ()

    try:
        s.cmdloop ("\n----\n"
                + "Welcome to the amazingly awesome shell for WG10 SmartCards :D\n"
                + "Remember to initialize the reader using the command 'init'\n"
                + "All commands that start with 'll_' are low level. "
                + "The rest of them are the ones meant to be used to automatically "
                + "interact with the SmartCard.\n\n"
                + "=> Execute 'help' to list all the available commands.\n"
                + "=> Execute 'get_status' to get info about the session key, NT...\n\n"
                + "=> To operate with a smartcard, you have to execute first 'connect'"
                + "\n----\n"
        )
    except KeyboardInterrupt as e:
        s.do_quit (None)
