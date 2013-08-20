#
#  $Id: config.py,v 1.3 2002/03/28 04:55:14 rob Exp $
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

__version__ = '$Id: config.py,v 1.3 2002/03/28 04:55:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import shlex, os, sys

# config file parser... commands end with a ; or eof, calls a
# function (or really a callable object, probably) with each one

class Error(Exception): pass

def read_config(filename, cmd_proc):
    lex = shlex.shlex(open(filename), filename)

    while 1:
        # collect a command
        cmd = []
        while 1:
            tok = lex.get_token()
            if not tok or tok == ';': break
            cmd.append(tok)

        try:
            if cmd: cmd_proc(cmd)
        except Error, s:
            sys.stderr.write(lex.error_leader())
            sys.stderr.write(str(s))
            sys.stderr.write('\n')
            sys.stderr.flush()

        if not tok: break
        
        
class CommandProcessor:
    def __call__(self, argv):
        cmd = argv[0]

        m = 'cmd_%s' % cmd
        if hasattr(self, m):
            getattr(self, m)(argv)

# ------------------------------------------------------------
# Pyrite Publisher specific stuff starts here
# ------------------------------------------------------------

def maybe_unquote(s):
    if len(s) > 1 and s[0] in '"\'' and s[0] == s[-1]:
        return s[1:-1]
    else:
        return s
    
class PPConfigProcessor(CommandProcessor):
    def __init__(self, plugins={}, instance=None):
        self.plugins = plugins
        self.vars = {}
        self.instance = instance

    def load(self, fn):
        if os.path.isfile(fn): read_config(fn, self)

    def has_key(self, k): return self.vars.has_key(k)
    def get(self, k, d=None): return self.vars.get(k,d)
    def __getitem__(self, k): return self.vars[k]
    
    def cmd_set(self, argv):
        argv = argv[1:]
        if len(argv) == 5:  # set <plugin>.<property> = <value>
            if argv[1] != '.' or argv[3] != '=':
                raise Error, 'set syntax error'
            pname = maybe_unquote(argv[0])
            if not self.plugins.has_key(pname):
                raise Error, 'plugin %s not found' % pname
            p = self.plugins[pname]
            propname = maybe_unquote(argv[2])
            if not p.has_property(propname):
                raise Error, 'plugin %s has no property %s' % (pname, propname)
            pd = p.getPropertyInfo(propname)
            if pd.read_only:
                raise Error, 'property %s.%s is read-only' % (pname, propname)
            value = eval(argv[4], p.__dict__.copy())
            if pd.indexed:
                v = getattr(p, propname)
                if type(v) != type([]):
                    raise Error, 'huh? property %s.%s is indexed, but is not a list?' % (pname, propname)
                v.append(value)
            else:
                setattr(p, propname, value)
        elif len(argv) == 3: # set <var> = <value>
            if argv[1] != '=':
                raise Error, 'set syntax error'
            self.vars[maybe_unquote(argv[0])] = eval(argv[2])
        else:
            raise Error, 'set syntax error'

    def cmd_priority(self, argv):
        argv = argv[1:]
        if len(argv) < 2 or len(argv) > 4: raise Error, 'priority syntax error'
        pname = maybe_unquote(argv[0])
        if not self.plugins.has_key(pname):
            raise Error, 'plugin %s not found' % pname
        plugin = self.plugins[pname]
        argv = argv[1:]

        pri = eval(argv[0])
        if type(pri) != type(1): raise Error, 'priority is not an integer'
        argv = argv[1:]

        inp = outp = None
        if argv:
            inp = maybe_unquote(argv[0])
            argv = argv[1:]

        if argv:
            outp = maybe_unquote(argv[0])

        plugin.set_priority(pri, inp, outp)
        
    def cmd_inputfilter(self, argv):
        argv = argv[1:]
        if len(argv) < 3: raise Error, 'inputfilter syntax error'
        intype = maybe_unquote(argv[0])
        outtype = maybe_unquote(argv[1])
        cmd = maybe_unquote(argv[2])

        self.instance.input_filters[(intype,outtype)] = cmd
        
