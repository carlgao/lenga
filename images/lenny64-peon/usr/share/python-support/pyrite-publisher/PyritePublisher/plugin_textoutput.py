#
#  $Id: plugin_textoutput.py,v 1.5 2002/07/15 21:40:28 rob Exp $
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

__version__ = '$Id: plugin_textoutput.py,v 1.5 2002/07/15 21:40:28 rob Exp $'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'


import sys
import dtkplugins

class FakeDocStream:
    def __init__(self, f=sys.stdout):
        self.f = f
	self.appinfo = None
	self.bookmarks = []
        self.annotations = []
	self.pos = 0
	
    def set_appinfo(self, a=''):
	self.appinfo = None

    def has_feature(self, f):
        return 1
    
    def bookmark(self, title, pos=None):
	if pos is None: pos = self.pos
	self.bookmarks.append((pos, title))

    def annotate(self, text, title='', pos=None):
        if pos is None: pos = self.pos
        self.annotations.append((pos, title, text))
        
    def write(self, data):
	self.pos = self.pos + len(data)
	self.f.write(data)

    def writelines(self, list):
	for l in list: self.write(l)

    def dump(self):
	if (self.dump_all or self.dump_appinfo) and self.appinfo:
	    self.f.write("\n*** Appinfo:\n")
	    self.f.write(repr(self.appinfo))
	    self.f.write("\n")

	if (self.dump_all or self.dump_bookmarks) and self.bookmarks:
            self.bookmarks.sort()
	    self.f.write("\n*** Bookmarks:\n")
	    for pos, t in self.bookmarks:
		self.f.write("(%9d) %s\n" % (pos, t))
	    self.f.write("\n")

        if (self.dump_all or self.dump_annotations) and self.annotations:
            self.annotations.sort()
            self.f.write("\n*** Annotations:\n")
            for pos, t, txt in self.annotations:
                self.f.write(">> (%9d) %s\n" % (pos, t))
                self.f.write(txt)
                self.f.write("\n")

    def close(self):
	self.dump()
        self.f.flush()
        if self.f is not sys.stdout and self.f is not sys.stderr:
            self.f.close()
    
	
class Plugin(dtkplugins.OutputPlugin):
    name = 'TextOutput'
    description = 'Text and debugging output.'

    links = [ (-1000, "doc-output", None),
              (-1000, "doc-only-output", None),
              (0, "text-output", None)]

    def __init__(self, *a, **kw):
        dtkplugins.OutputPlugin.__init__(self, *a, **kw)

        self._add_property('dump_bookmarks', 'Dump bookmarks', boolean=1)
        self._add_cli_option('dump_bookmarks', None, 'dump-bookmarks',
                             'Dump bookmarks',
                             boolean=1)
        self.dump_bookmarks = 0

        self._add_property('dump_annotations', 'Dump annotations', boolean=1)
        self._add_cli_option('dump_annotations', None, 'dump-annotations',
                             'Dump annotations',
                             boolean=1)
        self.dump_annotations = 0
        
        self._add_property('dump_appinfo', 'Dump appinfo', boolean=1)
        self._add_cli_option('dump_appinfo', None, 'dump-appinfo',
                             'Dump appinfo',
                             boolean=1)
        self.dump_appinfo = 0
        
        self._add_property('dump_all', 'Dump all metadata', boolean=1)
        self._add_cli_option('dump_all', 'D', 'dump-all',
                             'Dump all metadata',
                             boolean=1)
        self.dump_all = 0

        self._add_property('output_filename', 'Output filename')
        self._add_cli_option('output_filename', 'o', None,
                             'Output filename',
                             vtype='STR')
        self.output_filename = ''
        
    def open(self, chain, next, protocol, basename, *a, **kw):
        if self.output_filename: f = open(self.output_filename, 'w')
        else: f = sys.stdout
        
	self.doc = FakeDocStream(f)
        self.copyProperties(self.doc)
	return self.doc

    def close(self):
	self.doc = None
