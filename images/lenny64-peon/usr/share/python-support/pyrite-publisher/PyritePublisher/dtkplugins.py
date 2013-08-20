#
#  $Id: dtkplugins.py,v 1.14 2002/07/15 21:40:28 rob Exp $
#
#  Copyright 1999-2001 Rob Tillotson <rob@pyrite.org>
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
"""base types of plugins, etc.
"""

__version__ = '$Id: dtkplugins.py,v 1.14 2002/07/15 21:40:28 rob Exp $'

__copyright__ = 'Copyright 1999-2001 Rob Tillotson <rob@pyrite.org>'


import sys, os, urlparse, mimetypes, re
import dtkmain
from doc_database import DocWriteStream
import urllib

import plugin
from plugin import LOG_ERROR, LOG_WARNING, LOG_DEBUG, LOG_NORMAL

# *******************************************************************
# Callback/API object for plugins
# *******************************************************************
#class DTKCallback(plugin.Callback):
#    def __init__(self, *a, **kw):
#	apply(plugin.Callback.__init__, (self,)+a, kw)
    

# *******************************************************************
# Loader stuff
# *******************************************************************
#PLUGINS = [
#    'plugin_HTML', 'plugin_TaggedText', 'plugin_Text',
#    'plugin_RichReader', 'plugin_TealDoc',
#    'plugin_ztxtoutput',
#    'plugin_pdbinput', 'plugin_debugoutput',
#    ]


def load_all_plugins(callback=None):
    if globals().has_key('__file__') and (__file__[-3:] == '.py' or
                                          __file__[-4:] in ('.pyc','.pyo')):
        path = os.path.split(__file__)[0]
        if path not in sys.path:
            sys.path.append(path)

        # figure out what plugins are here
        if not path: path = '.' # for listdir
        p = {}
        for fn, ext in map(os.path.splitext, os.listdir(path)):
            if ext in ['.py', '.pyc', '.pyo'] and fn[:7] == 'plugin_' and not p.has_key(fn):
                p[fn] = fn
        PLUGINS = p.keys()
    else:
        # if we weren't loaded from a file, use metadata previously gathered
        # instead.
        try:
            import pp_meta
            PLUGINS = ['PyritePublisher.'+x for x in pp_meta.plugin_modules]
        except:
            PLUGINS = []
        path = ''

    pl = [ RawParserPlugin(api=callback) ]
    
    l = {}
    for p in pl: l[p.name] = p
    
    ldr = plugin.CallableLoader(callback)
    for p in ldr.load_plugins(PLUGINS, 'Plugin', api=callback):
        if p.usable(): # ignore plugins that claim not to work
            l[p.name] = p

    if path and path in sys.path:
        sys.path.remove(path)
        
    return l


# *******************************************************************
# Input plugin base class and raw plugin
# *******************************************************************

class DTKPlugin(plugin.PropertyMixin, plugin.CLIOptionMixin):
    links = []
    features = []
    def __init__(self, type='plugin', api=None):
	plugin.PropertyMixin.__init__(self,'Pyrite.Publisher.%s.%s' % (type, self.name))
	plugin.CLIOptionMixin.__init__(self, [])
	
	self._add_property('name', 'The name of this plugin', read_only=1)
	self._add_property('version', 'The version of this plugin', read_only=1)
	self._add_property('author', 'The author of this plugin', read_only=1)
	self._add_property('author_email', "The author's email address", read_only=1)
	self._add_property('description', 'A description of this plugin', read_only=1)

	self.chain = None
	self.next = None

        self.api = api

    def usable(self):
        return 1
    
    def log(self, s, level=plugin.LOG_NORMAL):
        self.api.log(level, self.name, s)

    def has_feature(self, f):
        return f in self.features
    
    def get_supported_links(self):
	return self.links

    def has_link(self, input, output=''):
        for pri, inp, outp in self.links:
            if (inp == input and outp == output) or \
               (inp == input and not output):
                return 1
            
    def set_priority(self, npri, input=None, output=None):
        l = []
        for pri, inp, outp in self.links:
            if inp == input and outp == output: pri = npri
            elif inp == input and output == None: pri = npri
            elif input == None and output == None: pri = npri
            l.append((pri, inp, outp))
        l.sort()
        self.links = l
        
    def open(self, chain, next, protocol, *a, **kw):
	self.chain = chain
	self.next = next
        self.protocol = protocol
	return self

    def close(self):
	self.chain = None
	self.next = None
	


class ParserPlugin(DTKPlugin):
    name = ''
    version = dtkmain.VERSION
    author = 'Rob Tillotson'
    author_email = 'rob@pyrite.org'
    description = ''

    def __init__(self, *a, **kw):
	DTKPlugin.__init__(self, 'Parser', **kw)

    def feed(self, data): pass
    def eof(self): pass

class RawParserPlugin(ParserPlugin):
    name = 'RawText'
    description = 'Processes raw input.'
    links = [ (0, "application/octet-stream", "doc-assembler") ]

    def feed(self, data):
	self.next.send_literal_data(data)

# *******************************************************************
# Output plugins base class and basic doc output plugin
# *******************************************************************

class AssemblerPlugin(DTKPlugin):
    name = ''
    version = dtkmain.VERSION
    author = 'Rob Tillotson'
    author_email = 'rob@pyrite.org'
    description = ''

    def __init__(self, *a, **kw):
	DTKPlugin.__init__(self, 'Assembler', **kw)

    
    
    
#
#  input.
#

class InputPlugin(DTKPlugin):
    name = ''
    version = dtkmain.VERSION
    author = "Rob Tillotson"
    author_email = "rob@pyrite.org"
    description = ""

    def __init__(self, *a, **kw):
	DTKPlugin.__init__(self, "Input", **kw)

    def handles_filename(self, fn):
	return None
    
    def open_input(self, fn):
	"""Open a data source.
	"""
	return (None, None)

    def close_input(self):
	pass
    
    

class OutputPlugin(DTKPlugin):
    name = ''
    version = dtkmain.VERSION
    author = "Rob Tillotson"
    author_email = "rob@pyrite.org"
    description = ""

    installable = 0
    
    def __init__(self, *a, **kw):
	DTKPlugin.__init__(self, "Output", **kw)

        # direct install helper support
        if self.installable:
            self._add_property('install', 'Install on handheld', boolean=1)
            self._add_cli_option('install', 'i', None,
                                 'Install on handheld',
                                 boolean=1)
            self.install = 0            

    def do_install(self, filenames):
        if not self.installable:
            return

        if self.install:
            installer = self.api.find_installer()
            if installer is None:
                self.log("can't figure out how to install", LOG_ERROR)

            installer.install(filenames)
                

            
    


class InstallerPlugin(DTKPlugin):
    name = ''
    version = dtkmain.VERSION
    author = "Rob Tillotson"
    author_email = "rob@pyrite.org"
    installer_name = ''
    installer_can_remove = 1
    installer_priority = 0
    
    def __init__(self, *a, **kw):
        DTKPlugin.__init__(self, "Installer", **kw)

        if self.installer_can_remove:
            self._add_property('keep_installed_files', 'Keep installed files', boolean=1)
            self._add_cli_option('keep_installed_files', None, 'keep',
                                 'Keep installed files',
                                 boolean=1)
            self.keep_installed_files = 0

    def installable_check(self):
        return None
    
    def install(self, filenames):
        pass
    
        
        
