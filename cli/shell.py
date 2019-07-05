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

import re
import binascii
import cmd

from Crypto.Cipher import DES3

# Smartcard automatic interaction
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest


# Custom modules
from crypto import wg10
from scard.observer import SmartCardObserver
from scard.commands import SmartCardCommands


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
        self.do_disconnect (args)
        print ("Bye :)")
        return True




    def do_init (self, args):
        """
        Initializes a Crypto object with the defined master key.

        SYNOPSIS
            init [-l] <master_key>

        DESCRIPTION
            -l  <HEX_VALUE> This option is only used when you're going to
                            do a "LOCAL" Internal Authenticate.

        @param master_key: hex string or int number (optional)
            - Hexadecimal string with the master key used to derive the keys
            - Integer number of your card
        """
        if args:
            try:
                binary_key_str = None

                if ("-l" in args):
                    binary_key_str = binascii.unhexlify (args.split(" ")[1])
                elif args.isdigit ():
                    # Only 16 Byte keys => at most 2 digits
                    if len (args) > 2:
                        print (ERROR_COLOR
                            + "ERROR: You can only initialize the default key with at "
                            + "most 2 digits"
                            + END_COLOR
                        )
                        return None
                    else:
                        binary_key_str = ("MASTERADMKEY_" + args.zfill (3))\
                                            .encode ("utf-8")
                else:
                    binary_key_str = binascii.unhexlify (args)

                self.crypto = wg10.Crypto (binary_key_str)

            except Exception as e:
                print (ERROR_COLOR
                    + "ERROR: Couldn't initialize the object -> " + str (e)
                    + END_COLOR
                )
                return None

        else:
            self.crypto = wg10.Crypto ()

        print ("Object correctly initialized with master key: 0x{:s}".format (
                binascii.hexlify (self.crypto.MASTER_KEY).decode ("utf-8")
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
#                print ("\nSending the command to sc...\n")
#                self.do_send_raw (binascii.hexlify (encrypted).decode("utf-8"))
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

        if not recv [0]:
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

        if not recv [0]:
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
        cmd = SmartCardCommands.INTERNAL_AUTHN (challenge)
        res = self.send (cmd)

        if not res [0]:
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

        if not res [0]:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1,SW2 == 0x90,0x00 -> Everything OK and no more data to read
        if res [1] != 0x90 or res [2] != 0x00:
            print ("ERROR: Expected response 0x90 0x00; but received '{:s} {:s}' instead"
                    .format (hex (res [1]), hex (res [2]))
            )
            return None

        recv = binascii.unhexlify ("".join ([ hex (x)[2:].zfill (2) for x in res [0] ]))

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

        if not recv [0]:
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

        if not recv [0]:
            print ("Couldn't get a response from the SmartCard")

        try:
            # Checks the response of the smartcard with the rest of the signature
            if recv[1] == 0x6A and recv[2] == 0x82:
                print (WARN_COLOR +"\nWARNING: The file is not or cannot be selected. "
                    + "Try to select it with: select_ef [your EF_ID] command.\n"
                    + END_COLOR
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

        hex_str = binascii.hexlify (args.encode ("utf-8"))
        list_name = [ int (hex_str [i : i + 2], 16) for i in range (0, len (hex_str), 2) ]

        cmd = SmartCardCommands.SELECT_NAME (list_name)
        recv = self.send (cmd)
        # Whether the command executed successfully or not, the selection changed
        self.selected_dir = None

        if not recv [0]:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if recv [1] == 0x61:

            cmd = SmartCardCommands.GET_RESPONSE (recv [2])
            recv = self.send (cmd)

            if not recv [0]:
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

        if not recv [0]:
            print ("Couldn't get a response from the SmartCard")
            return None

        # SW1 == 0x61 means that the process executed correctly and there's data to read
        # The number of bytes to read is encoded in SW2
        if recv [1] == 0x61:

            cmd = SmartCardCommands.GET_RESPONSE (recv [2])
            recv = self.send (cmd)

            if not recv [0]:
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

        if not recv [0]:
            print ("Couldn't get a response from the SmartCard")
            return None

        # Expected SW1 == 0x6C and SW2 = (bytes to read)
        if recv [1] == 0x6C:

            print ("Reading {:d} bytes from the file".format (recv [2]))
            cmd = SmartCardCommands.READ_BINARY (recv [2])
            recv = self.send (cmd)

            if not recv [0]:
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

        data = binascii.unhexlify (args)
        encrypted = b''

        try:
            if data:
                encrypted = DES3.new (self.crypto.SK
                                        , IV = b'\x00' * 8
                                        , mode = DES3.MODE_CBC
                        ).encrypt (data)

            cmd = SmartCardCommands.VERIFY_SECRET_CODE (binascii.hexlify (encrypted))
            self.send (cmd)
        except Exception as e:
            print (ERROR_COLOR
                + "ERROR: Couldn't verify the secret code -> " + str (e)
                + END_COLOR
            )
            return None

