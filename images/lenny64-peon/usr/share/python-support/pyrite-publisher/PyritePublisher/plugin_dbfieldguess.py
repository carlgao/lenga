#
#  $Id: plugin_dbfieldguess.py,v 1.2 2002/03/28 04:55:14 rob Exp $
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

__version__ = '$Id: plugin_dbfieldguess.py,v 1.2 2002/03/28 04:55:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import re, string

from dtkplugins import DTKPlugin, LOG_NORMAL, LOG_DEBUG, LOG_ERROR, LOG_WARNING
from dtkmain import ConversionError

import dtkmain

from dbprotocol import *

_rx_types = [
    (re.compile('^[01]$'), FLD_BOOLEAN),
    (re.compile('^[+-]?\d+$'), FLD_INT),
    (re.compile('^[+-]?\d+\.\d+$'), FLD_FLOAT),
    (re.compile('^\d+/\d+/\d+$'), FLD_DATE),
    (re.compile('^\d+:\d\d [aApP][mM]$'), FLD_TIME),
    ]

_included_types = { (FLD_BOOLEAN, FLD_INT) : None,
                    (FLD_BOOLEAN, FLD_FLOAT): None,
                    (FLD_INT, FLD_FLOAT): None,
                    }

_type_convert = { FLD_INT: int,
                  FLD_FLOAT: float,
                  FLD_BOOLEAN: lambda x: int(x and '1' or '0'),
                  }

class Plugin(DTKPlugin):
    name = 'GuessFields'
    description = 'Guess field types in a database'
    version = dtkmain.VERSION
    author = 'Rob Tillotson'
    author_email = 'rob@pyrite.org'

    links = [ (0, 'columnar-database', 'columnar-database') ]

    def open(self, chain, next, *a, **kw):
        DTKPlugin.open(self, chain, next)
        self.guesser = None
        self.recs = []
        return self
    
    def define_fields(self, fieldspecs):
        for spec in fieldspecs: spec.type = None # initialize for guessing
        self.guesser = TypeGuesser(fieldspecs, _rx_types, _included_types)
        
    def feed_record(self, rec):
        self.guesser(rec)
        self.recs.append(rec)

    def close(self):
        self.next.define_fields(self.guesser.fieldspecs)
        
        for rec in self.recs:
            self.next.feed_record(self.guesser.convert_rec(rec))
        
    
