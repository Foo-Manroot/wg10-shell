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

from enum import Enum

class SmartCardCommands (Enum):
    """
    Collection of lambda functions to build the proper messages
    """
    GET_RESPONSE = lambda length: [ 0, 0xc0, 0, 0, length ]
    INTERNAL_AUTHN = lambda challenge: [ 0x00, 0x88, 0x00, 0x00, 0x08 ] + challenge
    INTERNAL_AUTHN_LOCAL = lambda challenge: [ 0x00, 0x88, 0x00, 0x80, 0x08 ] + challenge
    SELECT_NAME = lambda name_hex: [ 0x00, 0xa4, 0x04, 0x00, len (name_hex) ] + name_hex
    SELECT_ID = lambda ident: [ 0x00, 0xa4, 0x02, 0x00, len (ident) ] + ident
    READ_BINARY = lambda le, offset, ef_id: [ 0x00, 0xB0, ef_id, offset, le ]
    VERIFY_SECRET_CODE = lambda secret_code: [ 0x00, 0x20, 0x00, 0x00, 0x08 ] + [ secret_code ]
