#
#  $Id: plugin_frotz.py,v 1.2 2002/02/05 12:06:14 rob Exp $
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

__version__ = '$Id: plugin_frotz.py,v 1.2 2002/02/05 12:06:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

from dtkplugins import DTKPlugin
import dtkmain
import mimetypes

class Plugin(DTKPlugin):
    name = 'Frotz'
    description = 'Z-Machine game to database converter'
    version = dtkmain.VERSION
    author = "Rob Tillotson"
    author_email = "rob@pyrite.org"

    links = [ (0, 'application/x-zmachine', 'pdb-output'), ]
    
    def __init__(self, *a, **kw):
        apply(DTKPlugin.__init__, (self,)+a, kw)

        # register zcode extensions since they aren't known to the
        # standard mimetypes module
        mimetypes.types_map['.z3'] = 'application/x-zmachine'
        mimetypes.types_map['.z5'] = 'application/x-zmachine'
        mimetypes.types_map['.z6'] = 'application/x-zmachine'
        mimetypes.types_map['.z8'] = 'application/x-zmachine'

        self.api.register_wildcard('*.z?', 'Z-Machine games')

        self._add_property('title', 'Game title')
        self._add_cli_option('title', 't', 'title',
                             'Game title',
                             vtype="STR")
        self.title = ''
        
    def open(self, chain, next, *a, **kw):
        self.pdb = next
        self.buf = ''

        self.next_id = 0xa5e001

        inf = {'type': 'ZCOD',
               'creator': 'Fotz',}
        if self.title: inf['name'] = self.title
        
        self.pdb.updateDBInfo(inf)
        
        return self

    def feed(self, data):
        self.buf = self.buf + data
        while len(self.buf) > 4096:
            b = self.buf[:4096]
            self.buf = self.buf[4096:]

            self.pdb.setRecord(0x60, self.next_id, 0, b)
            self.next_id = self.next_id + 1

    def eof(self):
        if self.buf:
            self.pdb.setRecord(0x60, self.next_id, 0, self.buf + ('\0' * (4096-len(self.buf))))
            self.next_id = self.next_id + 1
        self.buf = ''
        
    
