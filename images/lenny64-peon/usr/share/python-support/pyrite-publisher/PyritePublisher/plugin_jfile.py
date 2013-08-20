#
#  $Id: plugin_jfile.py,v 1.1 2002/03/26 12:56:06 rob Exp $
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

__version__ = '$Id: plugin_jfile.py,v 1.1 2002/03/26 12:56:06 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'


from dtkplugins import DTKPlugin, LOG_NORMAL, LOG_DEBUG, LOG_ERROR, LOG_WARNING
from dtkmain import ConversionError

import dtkmain

import struct, string, re

from dbprotocol import *

def pad(s, n):
    return (s[:n]+('\0'*n))[:n]

CURRENT_MARKER = 576

MAX_FIELDS = 50
MAX_FIELD_NAME_LENGTH = 20
MAX_DATA_LENGTH = 4000
MAX_FIND_STRING = 16
MAX_FILTER_STRING = 16

_types = { FLD_STRING : 0x0001,
           FLD_BOOLEAN: 0x0002,
           FLD_DATE   : 0x0004,
           FLD_INT    : 0x0008,
           FLD_FLOAT  : 0x0010,
           FLD_TIME   : 0x0020, }


def make_jfile_appinfo(fieldspecs):
    rec = string.join([pad(x.name,MAX_FIELD_NAME_LENGTH)+'\0' for x in fieldspecs],'')
    for n in range(MAX_FIELDS - len(fieldspecs)):
        rec = rec + ('\0'*(MAX_FIELD_NAME_LENGTH+1))

    # string fields only right now
    for x in fieldspecs:
        rec = rec + struct.pack('>H', _types[x.type])
        
    rec = rec + (struct.pack('>H',0x0000) * (MAX_FIELDS - len(fieldspecs)))

    rec = rec + struct.pack('>H', len(fieldspecs))
    rec = rec + struct.pack('>H', CURRENT_MARKER)

    # column widths
    # boolean only needs 15
    # int needs 5*len+3
    for x in fieldspecs:
        t = x.type
        if t == FLD_BOOLEAN: w = 15
        elif t == FLD_INT: w = x.max_length*5+3
        else: w = 80
        rec = rec + struct.pack('>H',w)
    rec = rec + (struct.pack('>H',80) * (MAX_FIELDS-len(fieldspecs)))

    rec = rec + struct.pack('>H',80) # showDataWidth

    # filters and sorts
    rec = rec + (5 * struct.pack('>H',0))

    rec = rec + '\0' * MAX_FIND_STRING
    rec = rec + '\0' * MAX_FIND_STRING

    # flags defunct in jfile 5
    rec = rec + '\0\0'

    # first column to show
    rec = rec + '\0\0'

    # extra data 1
    rec = rec + '\0\0\0\0' * MAX_FIELDS
    # ... and 2
    rec = rec + '\0\0\0\0' * MAX_FIELDS

    # extra chunk
    rec = rec + '\0\0'

    return rec


            
class Plugin(DTKPlugin):
    name = 'JFile'
    description = 'JFile database converter'
    version = dtkmain.VERSION
    author = 'Rob Tillotson'
    author_email = 'rob@pyrite.org'

    links = [ (-1, 'columnar-database', 'pdb-output') ]
    
    def __init__(self, *a, **kw):
        DTKPlugin.__init__(self, *a, **kw)

        self._add_property('title','Database title')
        self._add_cli_option('title','t','title','Database title',vtype="STR")
        self.title = ''
        
    def open(self, chain, next, *a, **kw):
        self.pdb = next

        inf = {'type': 'JfD5',
               'creator': 'JFi5',
               'version': 0x0801, # no security, jfile 5
               }
        if self.title: inf['name'] = self.title
        self.pdb.updateDBInfo(inf)
        
        self.uid = 0x6f0000
        
        self.field_names = []
        
        self.guesser = TypeGuesser()
        return self

    def define_fields(self, fieldspecs):
        self.fieldspecs = fieldspecs
        
    def feed_record(self, fields):
        rec = string.join([struct.pack('>H',len(str(x))+1) for x in fields], '')
        rec = rec + string.join(map(str, fields), '\0') + '\0'

        self.pdb.setRecord(0x40, self.uid, 0, rec)
        self.uid = self.uid + 1

    def close(self):
        self.pdb.setAppBlock(make_jfile_appinfo(self.fieldspecs))

    
    
