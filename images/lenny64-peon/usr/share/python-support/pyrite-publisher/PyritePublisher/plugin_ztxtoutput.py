#
#  $Id: plugin_ztxtoutput.py,v 1.8 2002/07/15 21:40:28 rob Exp $
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

__version__ = '$Id: plugin_ztxtoutput.py,v 1.8 2002/07/15 21:40:28 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import string, os

from dtkplugins import OutputPlugin
import ztxt

def valid_font(s):
    s = string.lower(s)
    if s not in ['standard','normal','large','bold','largebold','hk40','fixed']:
        raise OptionParsingError, 'font must be one of "normal", "large", "bold", "largebold", or "fixed"'
    if s == 'hk40': s == 'fixed'
    if s == 'standard': s == 'normal'
    return s

class Plugin(OutputPlugin):
    name = 'zTXT'
    description = 'Outputs to a zTXT (Gutenpalm) database.'
    
    links = [ (-1, "doc-output", "pdb-output") ]

    def __init__(self, *a, **kw):
        OutputPlugin.__init__(self, *a, **kw)

        self._add_property('title', 'The document title')
        self._add_cli_option('title','t','title',
                             'Set the document title',
                             vtype='STR')
        self.title = ''

        self._add_property('random_access', 'Compress for random access', boolean=1)
        self._add_cli_option('random_access', None, 'random-access',
                             'Toggle random access (default is on)',
                             boolean=1)
        self.random_access = 1

        self.api.register_task('doc2ztxt', 'Convert Doc to zTXT',
                               ['CopyDoc', 'zTXT'])
        self.api.register_task('mkztxt', 'Convert to zTXT',
                               ['zTXT'])
        self.api.register_task('raw2ztxt', 'Convert to zTXT without reformatting',
                               ['RawText','zTXT'])

        self.doc = None

    def open(self, chain, next, protocol, basename, *a, **kw):
        params = 0
        
        self.doc = ztxt.zTXTWriteStream(next,
                                        self.title and self.title or basename,
                                        self.random_access, params)
        return self.doc

    def close(self):
        self.doc = None
            
