#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Diverse utils for the Smartcard assignment.

Foo-Manroot - 2019


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

from enum import Enum

# Smartcard automatic interaction
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.util import toHexString



class SmartCardCommands (Enum):
    """
    Collection of lambda functions to build the proper messages
    """
    GET_RESPONSE = lambda length: [ 0, 0xc0, 0, 0, length ]
    INTERNAL_AUTHN = lambda challenge: [ 0x00, 0x88, 0x00, 0x00, 0x08 ] + challenge
    INTERNAL_AUTHN_LOCAL = lambda challenge: [ 0x00, 0x88, 0x00, 0x80, 0x08 ] + challenge
    SELECT_MF = lambda mf_id: [ 0x00, 0xa4, 0x04, 0x00, len (mf_id) ] + mf_id
    SELECT_DF = lambda df_id: [ 0x00, 0xa4, 0x04, 0x00, len (df_id) ] + df_id
    SELECT_EF = lambda ef_id: [ 0x00, 0xa4, 0x02, 0x00, len (ef_id) ] + ef_id



class SmartCardObserver (CardConnectionObserver):
    """
    Little interpreter for the SmartCard events.

    Modified version of
    https://pyscard.sourceforge.io/pyscard-framework.html#a-simple-apdu-tracer-and-interpreter
    """

    def update (self, cardconnection, ccevent):

        if ccevent.type == "connect":
            print ("Connected to " + cardconnection.getReader ())

#        elif ccevent.type == "disconnect":
#            print ("Disconnected from " + cardconnection.getReader ())

        elif ccevent.type == "command":

            str = toHexString (ccevent.args [0])
            print ('>', str)

        elif ccevent.type == "response":

            if [] == ccevent.args[0]:
                print ('< []', "%02X %02X" % tuple (ccevent.args [-2:]))
            else:
                print ('<\033[92m', toHexString (ccevent.args [0]), '\033[00m'
                    "%02X %02X" % tuple (ccevent.args [-2:])
                )



class Crypto ():
    """
    Global variables:

        MASTER_KEY (16 B): raw bytes -> The master key used to derive session keys
        self.NT (2 B): int -> Current value of the NT counter

        self.TK (16 B): int -> Temporal Key
        self.SK (16 B): int -> Session Key
    """

#    MASTER_KEY = "MASTERADMKEY_002".encode ("utf-8")


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

        @param rand: raw bytes
                Random number sent to the SmartCard


        @return: raw bytes
            The signature that corresponds to the returned message
        """
        # The random number has to be 8 Bytes long
        if len (random) != 8:
            print ("ERROR: he random number '{:s}' doesn't "
                    "have the correct length (8 Bytes).".format (
                        binascii.hexlify (random).decode ("utf-8")
                    )
            )
            return None


        if not self.derive_session_key (nt = nt):
            print ("ERROR: Couldn't derive session key")
            return None

        print ("Derived keys:\n\tTemporal -> {:s}\n\tSession ->  {:s}".format (
                binascii.hexlify (self.TK).decode ("utf-8")
                , binascii.hexlify (self.SK).decode ("utf-8")
            )
        )

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
            print ("ERROR: the command needs to be at least 5 Bytes long")
            return None

        data = command [5:]

        signature = self.sign (command)[-3:]

        encrypted = b''
        if data:
            encrypted = pyDes.triple_des (self.SK
                                    , IV = b'\x00' * 8
                                    , mode = pyDes.CBC
                                    , pad = '\x00'
                    ).encrypt (data)

        print ("Data:      '{:s}'".format (binascii.hexlify (data).decode ("utf-8")))
        print ("Encrypted: '{:s}'".format (binascii.hexlify (encrypted).decode ("utf-8")))
        print ("Signature: '{:s}'".format (binascii.hexlify (signature).decode ("utf-8")))


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
            print ("ERROR: The session key hasn't been initialized. Please call "
                    "verify_internal_authN () first")
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
        self.selected_mf = None
        self.selected_df = None
        self.selected_ef = None


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
        Initializes a Crypto object with the defined master key

        @param master_key: hex string (optional)
            Hexadecimal string with the master key used to derive the keys
        """
        if args:
            try:
                self.crypto = Crypto (binascii.unhexlify (args))
            except Exception as e:
                print ("ERROR: Couldn't initialize the object -> " + str (e))
                return None

        else:
            self.crypto = Crypto ()

        print ("Object correctly initialized with master key: 0x{:s}".format (
                binascii.hexlify (self.crypto.MASTER_KEY).decode ("utf-8")
            )
        )


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
            nt = int.from_bytes (binascii.unhexlify (s [0]), byteorder = "big")
            random = binascii.unhexlify (s [1])

            ret_val = self.crypto.gen_internal_authN (nt, random)
            if ret_val:
                print ("Response from the smartcard: {:s}".format (
                        binascii.hexlify (ret_val).decode ("utf-8")
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
            random = binascii.unhexlify (args)

            ret_val = self.crypto.gen_internal_authN (self.crypto.NT, random)
            if ret_val:
                print ("Response from the smartcard: {:s}".format (
                        binascii.hexlify (ret_val).decode ("utf-8")
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
            data = binascii.unhexlify (args)

            ret_val = self.crypto.sign (data)
            if ret_val:
                print (binascii.hexlify (ret_val))
                print (binascii.hexlify (data + ret_val [-3:]).decode ("utf-8"))
            else:
                print ("ERROR: Couldn't sign the data")

        except Exception as e:
            print ("ERROR: Couldn't sign data -> " + str (e))
            return None



    def do_get_status (self, args):
        """
        Prints the current status of the object (NT, master key...)
        """
        msg = "This value hasn't been initialized"
        print ("NT (counter) = "
                + (hex (self.crypto.NT) if self.crypto.NT else msg)
        )
        print ("Session Key =  "
                + (binascii.hexlify (self.crypto.SK).decode ("utf-8")
                    if self.crypto.SK else msg
                )
        )
        print ("Temporal Key = "
                + (binascii.hexlify (self.crypto.TK).decode ("utf-8")
                    if self.crypto.TK else msg
                )
        )
        print ("Master Key =   "
                + (binascii.hexlify (self.crypto.MASTER_KEY).decode ("utf-8")
                    if self.crypto.MASTER_KEY else msg
                )
        )
        print ("---------------------")
        print (
            ("Connected with " + self.sc_reader.connection.getReader ())
            if self.sc_reader else
            "Not connected to any reader"
        )
        print ("Currently selected MF: {:s}".format (
            self.selected_mf if self.selected_mf else " - ")
        )
        print ("Currently selected DF: {:s}".format (
            self.selected_df if self.selected_df else " - ")
        )
        print ("Currently selected EF: {:s}".format (
            self.selected_ef if self.selected_ef else " - ")
        )






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
            bin_nt = binascii.unhexlify (args)
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
            encrypted = self.crypto.encrypt (binascii.unhexlify (args))
            if encrypted:
                print (binascii.hexlify (encrypted))
            else:
                print ("Error encrypting command")

        except Exception as e:
            print ("ERROR: " + str (e))
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
            print ("No connection to the reader. Please, use the command 'connect'")
            return (None, None, None)

        else:
            try:

                ret = self.sc_reader.connection.transmit (cmd)
                if ret:
                    return ret
                else:
                    return (None, None, None)

            except Exception as e:
                print ("ERROR: " + str (e))
                return (None, None, None)




    def do_internal_authN (self, args):
        """
        Sends an 'internal authenticate' command to the smartcard with a super 'random'
        number: 0x0001020304050607

        The smartcard has to be connected first
        """
        # We could generate a random number; but we don't really care about it right now
        if("-l" in args):
            cmd = SmartCardCommands.INTERNAL_AUTHN_LOCAL ([0, 1, 2, 3, 4, 5, 6, 7])
        else:
            cmd = SmartCardCommands.INTERNAL_AUTHN ([0, 1, 2, 3, 4, 5, 6, 7])
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

        print ("==> Internal authentication completed. Verifying response")

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

        recv = "".join ([ hex (x)[2:].zfill (2) for x in res [0] ])

        if self.crypto.verify_internal_authN (recv, "0001020304050607") == 0:
            print ("Signature correct")
        else:
            print ("WARNING: Wrong signature")



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
        if recv [1] == 0x61:
            cmd = SmartCardCommands.GET_RESPONSE (recv [2])
            self.send (cmd)




    def do_send_signed (self, args):
        """
        Signes the provided command and sends it.

        @param bytes
            Hex string (case insensitive and can have whitespaces or not, doesn't matter)
        """
        # We don't care about the format -> remove spaces and group in pairs
        args = args.replace (" ", "")

        if (len (args) % 2) != 0:
            print ("ERROR: Odd-length string")
            return None

        cmd = [ int (args [i:i + 2], 16) for i in range (0, len (args), 2) ]
        signature = list (self.crypto.sign (bytes (cmd)))

        if not signature:
            print ("The signature couldn't be claculated")
            return None

        recv = self.send (cmd + signature [-3:])
        if not recv:
            print ("Couldn't get a response from the SmartCard")


        # Checks the response of the smartcard with the rest of the signature
        if recv [1] != 0x61:
            print ("WARNING: Couldn't verify the signature from the smartcard")

        else:
            # Should read 3 Bytes (the first three Bytes of the signature)
            cmd = SmartCardCommands.GET_RESPONSE (recv [2])
            verification = self.send (cmd)

            if (verification
                and
                (verification [2] == list (signature [:3]))
            ):
                print ("Signature returned from the smartcard verified")

            else:
                print ("WARNING: Verification of the signature failed.")



    def do_select_mf (self, args):
        """
        Select the specified Master File (root of the filesystem)

        @param bytes
            Hex string (case insensitive and can have whitespaces or not, doesn't matter)
            with the identifier (HEX ENCODED) of the MF
        """
        if not args:
            print ("No MF supplied. See 'help select_mf'")
            return None

        # We don't care about the format -> remove spaces and group in pairs
        args = args.replace (" ", "")

        if (len (args) % 2) != 0:
            print ("ERROR: Odd-length string")
            return None

        # We could generate a random number; but we don't really care about it right now
        mf_id = [ int (args [i:i + 2], 16) for i in range (0, len (args), 2) ]
        cmd = SmartCardCommands.SELECT_MF (mf_id)
        res = self.send (cmd)
        # Whether the command executed successfully or not, the selection changed
        self.selected_mf = None

        if not res:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if res [1] == 0x61:

            cmd = SmartCardCommands.GET_RESPONSE (res [2])
            res = self.send (cmd)

            if not res:
                print ("Couldn't get a response from the SmartCard")
                return None

            # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
            if (res [1] == 0x90) and (res [2] == 0x00):

                self.selected_mf = args
                print ("Selected MF '{:s}'".format (args))

            else:
                print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' "
                    "instead".format (hex (res [1]), hex (res [2]))
                )
                return None

        else:
            print ("MF not selected")




    def do_select_df (self, args):
        """
        Select the specified Dedicated File (directory in the filesystem)

        @param bytes
            Hex string (case insensitive and can have whitespaces or not, doesn't matter)
            with the identifier (HEX ENCODED) of the DF
        """
        if not args:
            print ("No DF supplied. See 'help select_df'")
            return None

        # We don't care about the format -> remove spaces and group in pairs
        args = args.replace (" ", "")

        if (len (args) % 2) != 0:
            print ("ERROR: Odd-length string")
            return None

        # We could generate a random number; but we don't really care about it right now
        df_id = [ int (args [i:i + 2], 16) for i in range (0, len (args), 2) ]
        cmd = SmartCardCommands.SELECT_DF (df_id)
        res = self.send (cmd)
        # Whether the command executed successfully or not, the selection changed
        self.selected_df = None

        if not res:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if res [1] == 0x61:

            cmd = SmartCardCommands.GET_RESPONSE (res [2])
            res = self.send (cmd)

            if not res:
                print ("Couldn't get a response from the SmartCard")
                return None

            # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
            if (res [1] == 0x90) and (res [2] == 0x00):

                self.selected_mf = args
                print ("Selected DF '{:s}'".format (args))

            else:
                print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' "
                    "instead".format (hex (res [1]), hex (res [2]))
                )
                return None

        else:
            print ("DF not selected")



    def do_select_ef (self, args):
        """
        Select the specified Elementary File (file in the filesystem)

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
            print ("ERROR: Odd-length string")
            return None

        # We could generate a random number; but we don't really care about it right now
        ef_id = [ int (args [i:i + 2], 16) for i in range (0, len (args), 2) ]
        cmd = SmartCardCommands.SELECT_EF (ef_id)
        res = self.send (cmd)
        # Whether the command executed successfully or not, the selection changed
        self.selected_ef = None

        if not res:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if res [1] == 0x61:

            cmd = SmartCardCommands.GET_RESPONSE (res [2])
            res = self.send (cmd)

            if not res:
                print ("Couldn't get a response from the SmartCard")
                return None

            # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
            if (res [1] == 0x90) and (res [2] == 0x00):

                self.selected_mf = args
                print ("Selected EF '{:s}'".format (args))

            else:
                print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' "
                    "instead".format (hex (res [1]), hex (res [2]))
                )
                return None

        else:
            print ("EF not selected")





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

#    ret = c.verify_internal_authN ("001854C51228DBCBE80C", "0001020304050607")
#
#    d = b"\x00\x01\x02\x03\x04\x05\x06\x07"
#    print (binascii.hexlify (c.sign (d * 3)))
#
#    if ret == 0:
#        print ("Verification done")
