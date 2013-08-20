#
#  $Id: plugin_basicdoc.py,v 1.1 2002/02/05 12:06:14 rob Exp $
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

__version__ = '$Id: plugin_basicdoc.py,v 1.1 2002/02/05 12:06:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import sys
from dtkplugins import AssemblerPlugin
from formatter import NullWriter

class BasicDocWriter(NullWriter):
    def __init__(self, doc=sys.stdout):
	NullWriter.__init__(self)

	self.doc = doc
	self.list_depth = 0
        self.footnote_marker_format = '[%d]'
        self.features = []
        
    def has_feature(self, f):
        return f in self.features or self.doc.has_feature(f)
    
    def close(self):
	self.flush()
	self.doc.close()
	self.doc = None

    def set_bookmark(self, s):
	"""Set a bookmark at the current output position.
	"""
	self.flush()
	self.doc.bookmark(s)

    def set_annotation(self, text, t=''):
        self.flush()
        self.doc.annotate(text, t)

    def mark_footnote(self, number=0):
        self.send_literal_data(self.footnote_marker_format % number)
        
    def send_heading(self, text, level=1):
	self.send_literal_data(text)
	self.send_line_break()

    def set_title(self, title):
	self.doc.name = title

    # standard writer API
    def reset(self):
	self.list_depth = 0

    def send_paragraph(self, blankline=0):
	self.doc.write('\n'*blankline)

    def send_line_break(self):
	self.doc.write('\n')

    def send_hor_rule(self, *a, **kw):
	char = kw.get('char','*')[:1]
	if char == '-': count = 39
	else: count = 26
	brk = kw.get('break','none')
	if brk in ['before','both']: self.doc.write('\n')
	self.doc.write(char * count)
	if brk in ['after','both']: self.doc.write('\n')

    def send_literal_data(self, data):
	self.doc.write(data)

    def send_flowing_data(self, data):
	self.doc.write(data)

    def send_label_data(self, data):
	self.doc.write('  '*self.list_depth)
	self.doc.write(data)
	if data and data[-1] not in ' \n\r\t':
	    self.doc.write(' ')

    def new_alignment(self, align):
	pass

    def new_font(self, font):
	pass

    def new_margin(self, margin, level):
	if margin is None or level == 0:
	    self.list_depth = 0
	elif margin in ['ol', 'ul']:
	    self.list_depth = level - 1

    def new_spacing(self, spacing):
	pass

    def new_styles(self, styles):
	pass

    
class Plugin(AssemblerPlugin):
    name = 'BasicDoc'
    description = 'Assembles a standard text document.'

    links = [ (10, "doc-assembler", "doc-output") ]

    writerclass = BasicDocWriter

    def __init__(self, *a, **kw):
	apply(AssemblerPlugin.__init__, (self,)+a, kw)
	self.writer = None

	self._add_cli_option('footnote_marker_format', None, 'footnote-marker-format',
                             'Footnote marker format',
                             vtype="STR")
        self._add_property('footnote_marker_format', 'Footnote marker format')
        self.footnote_marker_format = '[%d]'
        
    def open(self, chain, next, *a, **kw):
	self.writer = self.writerclass(next)
        self.copyProperties(self.writer)
	return self.writer

    def close(self):
	self.writer.close()
	self.writer = None
    

