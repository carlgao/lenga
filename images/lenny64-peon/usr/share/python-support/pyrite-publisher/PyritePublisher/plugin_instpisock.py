#
#  $Id: plugin_instpisock.py,v 1.1 2002/02/05 12:06:14 rob Exp $
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

__version__ = '$Id: plugin_instpisock.py,v 1.1 2002/02/05 12:06:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

from dtkplugins import InstallerPlugin, LOG_ERROR, LOG_DEBUG, LOG_NORMAL

import os

class Plugin(InstallerPlugin):
    name = 'pisockInstall'
    description = 'Installer that uses python-libpisock.'
    installer_name = 'pisock'
    installer_priority = -1
    installer_can_remove = 1

    def __init__(self, *a, **kw):
        InstallerPlugin.__init__(self, *a, **kw)

        self._add_property('port', 'Port handheld is attached to')
        self._add_cli_option('port', None, 'port',
                             'Port handheld is attached to',
                             vtype="NAME")
        self.port = '/dev/pilot'
        
    def installable_check(self):
        try:
            import pisock
            return 1
        except:
            return 0

    def install(self, filenames):
        import pisock

        sd = pisock.pi_socket(pisock.PI_AF_SLP, pisock.PI_SOCK_STREAM, pisock.PI_PF_PADP)
        if not sd:
            self.log("failed to create socket", LOG_ERROR)
            return
        if (pisock.pi_bind(sd, (pisock.PI_AF_SLP, self.port))) == -1:
            self.log("failed to bind socket", LOG_ERROR)
            return
        if (pisock.pi_listen(sd, 1)) == -1:
            self.log("failed to listen on socket", LOG_ERROR)
            return
        ret = pisock.pi_accept(sd)
        if ret == -1:
            self.log("failed to accept connection", LOG_ERROR)
            return
        socket = ret[0]
        pisock.dlp_OpenConduit(socket)
        #user_info = pisock.dlp_ReadUserInfo(socket) # not used yet
        
        if type(filenames) == type(''): filenames = [filenames]
        for fn in filenames:
            f = pisock.pi_file(fn)
            f.install(socket)
            del f
            if not self.keep_installed_files:
                os.unlink(fn)
                
        # write back user info... not yet

        pisock.dlp_AddSyncLogEntry(socket, "Pyrite Publisher install completed.")
        pisock.pi_close(socket)
        
        
