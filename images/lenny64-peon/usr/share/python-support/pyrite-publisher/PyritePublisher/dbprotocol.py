#
#  $Id: dbprotocol.py,v 1.1 2002/03/26 12:56:06 rob Exp $
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
"""Pyrite Publisher Database Protocol Support

This module provides support for the Pyrite Publisher protocol
'columnar-database', which is used for simple flat-file databases like
those found in CSV files and Palm applications like JFile, MobileDB,
and Handbase.  Primarily, it provides classes for handling metadata
about the columns in the database.

The field types supported by this module, their identifiers (defined in
this module as constants), and their internal representations are as
follows:

  FLD_STRING  - a string
    Represented internally by a string.
  FLD_INT     - an integer
    Represented internally by an integer.
  FLD_FLOAT   - a floating-point number
    Represented internally by a float.
  FLD_BOOLEAN - a true or false value
    Represented internally by an integer 0 or 1.
  FLD_DATE    - a date (without time)
    Represented internally by a string.
  FLD_TIME    - a time (without date)
    Represented internally by a string.

Objects implementing the columnar-database protocol have the following
methods:

  define_fields(speclist)
    REQUIRED.  Called by the upstream plugin before any records are
    fed downstream.  The parameter is a list of FieldSpec objects which
    describe the columns in the database.

  feed_record(list)
    REQUIRED.  Called by the upstream plugin once for each record.  The
    parameter is a list of values contained in that record, in their
    internal representation.
"""

__version__ = '$Id: dbprotocol.py,v 1.1 2002/03/26 12:56:06 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import os

import config

FLD_STRING = 'string'
FLD_INT = 'int'
FLD_FLOAT = 'float'
FLD_BOOLEAN = 'boolean'
FLD_DATE = 'date'
FLD_TIME = 'time'

class FieldSpec:
    """Columnar database field specification.
    """
    def __init__(self, name, type=FLD_STRING, **kw):
        self.name = name
        self.type = type
        self.max_length = 0
        
        for k,v in kw.items():
            setattr(self, k, v)

    def __str__(self):
        s = '<Field: %s [%s]' % (self.name, self.type)
        l = []
        for k,v in self.__dict__.items():
            if k not in ('name','type'):
                l.append('%s=%s' % (k, repr(v)))
        if l: s = s + ' (%s)' % ' '.join(l)
        s = s + '>'
        return s

    def __repr__(self):
        return self.__str__()
    
    def setFromConfig(self, k, v):
        setattr(self, k, v)

    def __getattr__(self, k, v):
        return None
    
# field "name" type <flags>;
# values "name" <value> ... ;


_type_names = {
    'string' : FLD_STRING,
    'str': FLD_STRING,
    'int': FLD_INT,
    'integer': FLD_INT,
    'float': FLD_FLOAT,
    'bool': FLD_BOOLEAN,
    'boolean': FLD_BOOLEAN,
    'checkbox': FLD_BOOLEAN,
    'check': FLD_BOOLEAN,
    'toggle': FLD_BOOLEAN,
    }

class DBSpecCmdProc(config.CommandProcessor):
    def __init__(self):
        self.fields = {}
        self.field_order = []
        
    def load(self, fn):
        if os.path.isfile(fn): config.read_config(fn, self)

    def cmd_field(self, argv):
        argv = argv[1:]
        if len(argv) < 1: raise config.Error, 'field syntax error'
        
        name = config.maybe_unquote(argv[0])
        argv = argv[1:]
        fspec = FieldSpec(name)

        if not argv:
            fspec.setFromConfig("type", FLD_STRING)
        else:
            t = config.maybe_unquote(argv[0])
            if not _type_names.has_key(t):
                raise config.Error, 'unknown field type %s' % t
            fspec.setFromConfig("type", _type_names[t])
            argv = argv[1:]

            while argv:
                a = config.maybe_unquote(argv[0])
                argv = argv[1:]
                if not argv: fspec.setFromConfig(a, 1)
                else:
                    v = config.maybe_unquote(argv[0])
                    argv = argv[1:]
                    fspec.setFromConfig(a, v)
                    
        self.fields[name] = fspec
        self.field_order.append(fspec)

    def cmd_values(self, argv): # values for popup list
        argv = argv[1:]
        if not argv: raise config.Error, "not enough arguments for 'values'"
        
        try:
            fnum = int(argv[0])
            fspec = self.field_order[fnum]
        except:
            fspec = self.fields[config.maybe_unquote(argv[0])]

        fspec.setFromConfig('values', map(config.maybe_unquote, argv[1:]))



class TypeGuesser:
    """Type guesser for the columnar database protocol.
    This class implements a simple type-guesser which takes a series of
    records with string values and tries to guess what type the values
    *should* be.  To accomplish this, it uses a set of regular expressions
    which match the string representations of other data types, and a set
    of type-inclusion rules.  (These rules are used to handle situations
    where more than one regular expression might match a particular value
    -- for example, an integer is also a valid floating point value.) As
    records are fed to it, it updates its guesses as to the type of each
    column.  If the values in a column don't consistently match any
    particular type, it will be declared to be a string.

    At the same time, it keeps track of field lengths to determine the
    largest required field size, and will in the future be expanded to
    collect even more information about the data passing through it.
    """


    def __init__(self, fields=[], rx_types=[], included_types={},
                 converters={}):
        self.fieldspecs = fields
        self.rx_types = rx_types
        self.included_types = included_types
        self.converters = converters
        
    def guess(self, s):
        for rx, typ in self.rx_types:
            if rx.match(s): return typ
        return FLD_STRING

    def __call__(self, fields):
        if not self.fieldspecs:
            self.fieldspecs = FieldSpec('', None)
            
        # now try to guess types
        for x in range(len(fields)):
            f = fields[x]
            t = self.fieldspecs[x]
            
            if t.type != FLD_STRING:
                t0 = self.guess(f)
                if t.type is None:
                    print t, t0, f
                    t.type = t0
                elif t.type != t0:
                    print t, t0, f
                    if self.included_types.has_key((t.type,t0)):
                        t.type = t0
                    else:
                        t.type = FLD_STRING

            if len(f) > self.fieldspecs[x].max_length: self.fieldspecs[x].max_length = len(f)

    def convert_rec(self, rec):
        ret = []
        for x in range(len(rec)):
            conv = self.converters.get(self.fieldspecs[x].type)
            if conv: ret.append(conv(rec[x]))
            else: ret.append(rec[x])
        return ret

if __name__ == '__main__':
    import sys
    from pprint import pprint
    
    c = DBSpecCmdProc()
    c.load(sys.argv[1])
    pprint(c.field_order)
    
