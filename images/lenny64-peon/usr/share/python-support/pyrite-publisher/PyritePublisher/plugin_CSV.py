#
#  $Id: plugin_CSV.py,v 1.1 2002/03/26 12:56:06 rob Exp $
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

__version__ = '$Id: plugin_CSV.py,v 1.1 2002/03/26 12:56:06 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'


from dtkplugins import ParserPlugin, LOG_ERROR, LOG_NORMAL, LOG_DEBUG, LOG_WARNING
from dbprotocol import *

import string


class CSVError(Exception): pass

class CSVParser:
    def __init__(self):
        self.fields = []
        self.buf = ''

        self.comment_marker = '#'
        self.field_separator = ','
        self.escape_double_quote = 1
        self.skip_blank_lines = 1
        
        self._state = 'start-field'
        self._accum = ''
        
    def flush(self):
        self._state = 'start-field'
        self._accum = ''
        self.buf = ''
        self.fields = []
        
    def __parse(self):
        x = 0
        done = 0
        
        while x < len(self.buf):
            c = self.buf[x]
            # start-field state: looking for beginning of field
            #   skip whitespace, separator means field was empty
            if self._state == 'start-field':
                if c == ' ' or c == '\t':
                    x = x + 1
                    continue
                elif c == '\n':
                    done = 1
                    x = x + 1
                    break
                elif c == '"':
                    self._state = 'quoted-string'
                elif c == self.field_separator:
                    self.fields.append('')
                else:
                    self._accum = self._accum + c
                    self._state = 'in-field'
            elif self._state == 'in-field':
                if c == self.field_separator:
                    self.fields.append(self._accum.strip())
                    self._accum = ''
                    self._state = 'start-field'
                elif c == '\n':
                    self.fields.append(self._accum.strip())
                    self._accum = ''
                    self._state = 'start-field'
                    done = 1
                    x = x + 1
                    break
                elif c == '"' and self.escape_double_quote and x < len(self.buf)-1 \
                   and self.buf[x+1] == '"':
                    x = x + 1 # eat second quote
                    self._accum = self._accum + '"'
                else:
                    self._accum = self._accum + c
            elif self._state == 'quoted-string':
                if c == '"':
                    if self.escape_double_quote and x < len(self.buf)-1 and self.buf[x+1] == '"':
                        x = x + 1
                        self._accum = self._accum + '"'
                    else:
                        self.fields.append(self._accum)
                        self._accum = ''
                        self._state = 'after-quoted-string'
                else:
                    self._accum = self._accum + c
            elif self._state == 'after-quoted-string':
                if c == '\n':
                    done = 1
                    x = x + 1
                    self._state = 'start-field'
                    break
                elif c == ' ' or c == '\t':
                    x = x + 1
                    continue
                elif c == self.field_separator:
                    self._state = 'start-field'
                else:
                    self.flush()
                    raise CSVError, "text after quote"

            x = x + 1

        self.buf = self.buf[x:]
        if done:
            f = self.fields
            self.fields = []
            return f

    def feed(self, text=''):
        self.buf = self.buf + text
        
        f = self.__parse()
        while f is not None:
            if f or not self.skip_blank_lines: self.handle_line(f)
            f = self.__parse()

    def eof(self):
        self.feed('\n')
        
    def handle_line(self, fields):
        print fields
        

class PPCSVParser(CSVParser):
    def __init__(self, next):
        CSVParser.__init__(self)
        
        self.next = next
        self.field_specs = 0
        
    def handle_line(self, fields):
        if self.use_field_names and not self.field_specs:
            self.field_specs = [FieldSpec(x, FLD_STRING) for x in fields]
            self.next.define_fields(self.field_specs)
        else:
            if not self.field_specs:
                self.field_specs = [FieldSpec("Field%d" % x, FLD_STRING) \
                                    for x in range(len(fields))]
                self.next.define_fields(self.field_specs)
            self.next.feed_record(fields)

    def eof(self):
        CSVParser.eof(self)
        
class Plugin(ParserPlugin, CSVParser):
    name = 'CSV'
    description = 'Comma-separated-values parser.'

    links = [ (0, 'text/comma-separated-values', 'columnar-database'),
              (-100, 'text/plain', 'columnar-database'),
              (-100, 'application/octet-stream', 'columnar-database'),
              ]
    
    def __init__(self, *a, **kw):
        ParserPlugin.__init__(self, *a, **kw)

        self._add_property('use_field_names', 'Get field names from first line', boolean=1)
        self._add_cli_option('use_field_names', None, 'use-field-names',
                             'Get field names from first line',
                             boolean=1)
        self.use_field_names = 0
        
    def open(self, chain, next, *a, **kw):
        ParserPlugin.open(self, chain, next, *a, **kw)
        self.parser = PPCSVParser(next)
        self.copyProperties(self.parser)
        self.ttbl = string.maketrans('','')
        return self
    
    def feed(self, data):
        l = string.translate(data, self.ttbl, '\r')
        self.parser.feed(l)

    def eof(self):
        self.parser.eof()
        
    
