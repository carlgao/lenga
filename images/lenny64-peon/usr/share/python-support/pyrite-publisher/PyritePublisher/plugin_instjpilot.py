#
#  $Id: plugin_instjpilot.py,v 1.1 2002/02/05 12:06:14 rob Exp $
#
#  Copyright 2001 Rob Tillotson <rob@pyrite.org>
#  All Rights Reserved
#
#  Permission to use, copy, modify, and distribute this software and
#  its documentation for any purpose and without fee or royalty is
#  hereby granted, provided that the above copyright notice appear in
#  all copies and that both the copyright notice and this permission
#  notice appear in supporting documentation or portions thereof,
#  including modifications, that you you make.
#
#  THE AUTHOR ROB TILLOTSON DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
#  RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
#  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
#  CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE!
#
"""
"""

__version__ = '$Id: plugin_instjpilot.py,v 1.1 2002/02/05 12:06:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import sys, os, string

from dtkplugins import InstallerPlugin

class Plugin(InstallerPlugin):
    name = 'JPilotInstall'
    description = 'Installer that uses jpilot.'
    installer_name = 'jpilot'
    installer_priority = 0
    installer_can_remove = 0
    
    def installable_check(self):
        if os.path.isdir(os.path.expanduser('~/.jpilot')):
            return 1

    def install(self, filenames):
        if type(filenames) == type(''): filenames = [filenames]
        jfn = os.path.expanduser('~/.jpilot/jpilot_to_install')
        q = open(jfn).readlines()
        o = open(jfn,'a')
        for fn in filenames:
            ifn = os.path.abspath(fn)
            if ifn not in map(string.strip, q):
                o.write(ifn+'\n')
