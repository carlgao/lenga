#
#  $Id: plugin_TealDoc.py,v 1.6 2002/02/05 12:06:14 rob Exp $
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
"""
"""

__version__ = '$Id: plugin_TealDoc.py,v 1.6 2002/02/05 12:06:14 rob Exp $'

__copyright__ = 'Copyright 1999-2001 Rob Tillotson <rob@pyrite.org>'

import string

# ack!  I need __!
import metrics

import plugin_basicdoc

# teal_header_attrs = {
#     1: {'FONT': '2', 'ALIGN': 'CENTER', 'STYLE': 'NORMAL'},
#     2: {'FONT': '1', 'ALIGN': 'LEFT', 'STYLE': 'UNDERLINE'},
#     3: {'FONT': '1', 'ALIGN': 'LEFT', 'STYLE': 'NORMAL'},
#     4: {'FONT': '0', 'ALIGN': 'LEFT', 'STYLE': 'UNDERLINE'},
#     5: {'FONT': '0', 'ALIGN': 'LEFT', 'STYLE': 'UNDERLINE'},
#     6: {'FONT': '0', 'ALIGN': 'LEFT', 'STYLE': 'UNDERLINE'}
#     }
# teal_header_fonts = {
#     1: 2,
#     2: 1,
#     3: 1
#     }
# teal_default_header_attrs = {'FONT': '0', 'ALIGN': 'LEFT', 'STYLE': 'NORMAL'}

def teal_header_style(s):
    l = string.split(s)
    d = {}
    if 'large' in l and 'bold' in l: d['FONT'] = 3
    elif 'large' in l: d['FONT'] = 2
    elif 'bold' in l: d['FONT'] = 1
    else: d['FONT'] = 0

    if 'right' in l: d['ALIGN'] = 'RIGHT'
    elif 'center' in l: d['ALIGN'] = 'CENTER'
    else: d['ALIGN'] = 'LEFT'

    if 'underline' in l: d['STYLE'] = 'UNDERLINE'
    elif 'invert' in l: d['STYLE'] = 'INVERT'

    return d


class TealDocWriter(plugin_basicdoc.BasicDocWriter):
    def __init__(self, *a, **kw):
	apply(plugin_basicdoc.BasicDocWriter.__init__, (self,)+a, kw)
	self.teal_bookmarks = 0
	self.features.append('richtext')
    def send_raw_tag(self, tagname, attr={}):
	self.flush()
	self.doc.write('<'+tagname)
	if attr:
	    self.doc.write(' ')
	    self.doc.write(string.join(map(lambda x: '%s=%s' % x, attr.items())))
	self.doc.write('>')
	
    def set_bookmark(self, s):
	if self.teal_bookmarks:
	    self.send_raw_tag('BOOKMARK',{'NAME':'"%s"' % s[:15]})
	else:
	    plugin_basicdoc.BasicDocWriter.set_bookmark(self, s)

    def send_heading(self, text, level=1):
        if hasattr(self, 'h%s_style' % level):
            s = getattr(self, 'h%s_style' % level)
        else:
            s = 'normal left'
        style = teal_header_style(s)
        
	l = metrics.wordwrap(text, max_width=160,
			     font=style.get('FONT',0))
	for t in l:
	    d = {'TEXT': '"%s"' % t}
	    d.update(style)
	    self.send_raw_tag('HEADER', d)
	    if not d.get('FONT') == 2:
		self.send_line_break()
	if d.get('FONT') == 2:
	    self.send_line_break()

    def send_hor_rule(self, *a, **kw):
	# later, do things based on 'break' and 'char'
	self.send_raw_tag('HRULE')
	self.doc.write('\n')
	
	
class Plugin(plugin_basicdoc.Plugin):
    name = 'TealDoc'
    description = 'Assembles a TealDoc-enhanced document.'

    links = [ (0, "doc-assembler", "doc-only-output") ]

    writerclass = TealDocWriter

    def __init__(self, *a, **kw):
        apply(plugin_basicdoc.Plugin.__init__, (self,)+a, kw)

        #self._add_cli_option("h1_style", None, "h1-style",
        #                     "Heading 1 style",
        #                     vtype="STR")
        self._add_property("h1_style", "Heading 1 style")
        self.h1_style = "large"

        self._add_property("h2_style", "Heading 2 style")
        self.h2_style = "bold underline"

        self._add_property("h3_style", "Heading 2 style")
        self.h3_style = "bold"
        
        self._add_property("h4_style", "Heading 2 style")
        self.h4_style = "underline"
        
        self._add_property("h5_style", "Heading 2 style")
        self.h5_style = "underline"
        
        self._add_property("h6_style", "Heading 2 style")
        self.h6_style = "underline"

        self.api.register_task("mktealdoc", "Convert to TealDoc",
                               ['TealDoc'])
        
