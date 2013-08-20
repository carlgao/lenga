#
#  $Id: plugin_pdboutput.py,v 1.4 2002/07/15 21:40:28 rob Exp $
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
"""Generic Palm database output plugin.

This simple plugin allows the previous plugin in the chain to
write a pdb/prc file in whatever arbitrary manner it wants.
The value passed to the previous plugin is simply a prc.File
instance.
"""

__version__ = '$Id: plugin_pdboutput.py,v 1.4 2002/07/15 21:40:28 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import os, time

from dtkplugins import OutputPlugin
import prc

# from the python cookbook
_num_rep = {}
for x in 'abcdefghijklmnopqrstuvwxyz':
    _num_rep[ord(x)-ord('a')+10] = x
    
def decimalToN(num,n):
    new_num_string=''
    current=num
    while current!=0:
        remainder=current%n
        if 36>remainder>9:
            remainder_string=_num_rep[remainder]
        elif remainder>=36:
            remainder_string='('+str(remainder)+')'
        else:
            remainder_string=str(remainder)
        new_num_string=remainder_string+new_num_string
        current=current/n
    return new_num_string

_id_begin = 1017175873
def gen_id():
    s = decimalToN(long((time.time()-1015000000)*10), 36)
    if len(s) < 6: return ('000000'+s)[-6:]

class Plugin(OutputPlugin):
    name = 'PDBOutput'
    description = 'Generic Palm database output'
    installable = 1
    
    links = [ (0, "pdb-output", None) ]
    
    def __init__(self, *a, **kw):
        apply(OutputPlugin.__init__, (self,)+a, kw)

	self._add_property('output_dir', 'Output directory')
        self._add_cli_option('output_dir', 'd', 'output-directory',
                             'Set the output directory',
                             vtype="STR")
        self.output_dir = '.'

        self._add_property('output_filename', 'Output filename')
        self._add_cli_option('output_filename', 'o', None,
                             'Set the output filename',
                             vtype="STR")
        self.output_filename = ''

        self._add_property('unique_names', 'Guarantee unique DB names')
        self._add_cli_option('unique_names', None, 'unique-names',
                             'Guarantee unique DB names', boolean=1)
        self.unique_names = 0
        
    def open(self, chain, next, protocol, basename, *a, **kw):
        if self.output_filename: fn = self.output_filename
        else: fn = os.path.join(self.output_dir, basename+'.pdb')

        self.filename = fn
        self.pdb = prc.File(fn, read=0, write=1, info={'name': basename})
        
        return self.pdb

    def close(self):
        if self.unique_names:
            id = gen_id()
            oldname = self.pdb.getDBInfo().get('name','')
            newname = (oldname + ' '*31)[:31-len(id)]+id
            self.pdb.updateDBInfo({'name': newname})
        self.pdb.close()
        self.pdb = None
        if self.install:
            self.do_install(self.filename)
