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
from Crypto.Cipher import DES3


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
        TK1 = DES3.new (deskey).encrypt (data)

        # 3DES (MK2 || MK1, data)
        deskey = self.MASTER_KEY [8:] + self.MASTER_KEY [:8]
        TK2 = DES3.new (deskey).encrypt (data)

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
        SK1 = DES3.new (deskey).encrypt (data)

        # 3DES (MK2 || MK1, data)
        deskey = self.MASTER_KEY [8:] + self.MASTER_KEY [:8]
        SK2 = DES3.new (deskey).encrypt (data)

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
        calc_signature = DES3.new (self.TK).encrypt (rand)

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
                        binascii.hexlify (random).decode ("utf-8")
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

        calc_signature = DES3.new (self.TK).encrypt (random)
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
            encrypted = DES3.new (self.SK
                                    , IV = b'\x00' * 8
                                    , mode = DES3.MODE_CBC
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
                prev_block = DES3.new (self.SK [:8]).encrypt (current_block)
            else:
                signature = DES3.new (self.SK).encrypt (current_block)

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


