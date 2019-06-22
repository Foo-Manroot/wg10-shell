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

from cli.shell import Shell

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
