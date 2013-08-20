#
#  $Id: plugin_RichReader.py,v 1.5 2002/02/05 12:06:14 rob Exp $
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

__version__ = '$Id: plugin_RichReader.py,v 1.5 2002/02/05 12:06:14 rob Exp $'

__copyright__ = 'Copyright 1999-2001 Rob Tillotson <rob@pyrite.org>'

import dtkplugins
import plugin_basicdoc

import string

def rr_style(s):
    """Convert a style spec to a RichReader font byte
    """
    b = 0
    for t in map(string.lower, string.split(s)):
	if t == 'normal' or t == 'medium': b = b | 0x40
	elif t == 'small': b = b | 0x20
	elif t == 'large': b = b | 0x60
	elif t == 'bold': b = b | 0x04
	elif t == 'italic': b = b | 0x02
	elif t == 'fixed': b = b | 0x08
	elif t == 'underline': b = b | 0x01
	elif t == 'dotted' or t == 'dotted-underline': b = b | 0x10
    return b

def rr_justify(s):
    s = string.split(s)
    if 'center' in s: return 0x83
    elif 'right' in s: return 0x81
    else: return 0x80

def rr_indent(x):
    return 0xc0 | x

def rr_hang_indent(x):
    return 0xf0 | x

class RichReaderDocWriter(plugin_basicdoc.BasicDocWriter):
    def __init__(self, *a, **kw):
	apply(plugin_basicdoc.BasicDocWriter.__init__, (self,)+a, kw)
	self.current_style = 0x40
	self.features.append('richtext')
        
    def send_code(self, code):
	self.flush()
	self.doc.write(chr(0x7f)+chr(code))

    def send_hor_rule(self, *a, **kw):
	self.send_code(0x8c)
	self.doc.write('\n')
	
    def send_heading(self, text, level=1):
        # get header style
        if hasattr(self, 'h%s_style' % level):
            s = getattr(self, 'h%s_style' % level)
        else:
            s = 'normal left'
        #s, j = rr_header_styles.get(level, rr_default_header_style)
	self.send_code(rr_justify(s))
	self.send_code(rr_style(s))
	self.doc.write(text)
	self.doc.write('\n')
	self.send_code(rr_style('normal'))
	self.send_code(rr_justify('left'))

    def send_label_data(self, data):
	self.doc.write(data+' ')
    
    def new_margin(self, kind, depth):
	if depth > 3: depth = 3
	self.send_code(0xc0 | (depth << 1))
	if kind in ['ol', 'ul', 'dl'] and depth > 0:
	    self.send_code(0xfe)
	else:
	    self.send_code(0xf0)
	    
    # note: to get underlining, will need to make a new subclass of
    # formatter, and override it to use 5-elt font tuples instead of 4-elt.
    def new_font(self, font):
	if font is not None:
	    sz, it, bd, tt = font[:4]
	else:
	    sz = it = bd = tt = 0
	    
	# nothing with size yet
	b = self.current_style
	#print "current style 0x%02x" % b
	if it: b = b | 0x02
	else: b = b & ~0x02
	if bd: b = b | 0x04
	else: b = b & ~0x04
	if tt: b = b | 0x08
	else: b = b & ~0x08
	#print font, "= 0x%02x" % b
	self.send_code(b)
	
	self.current_style = b

    def new_styles(self, styles):
	b = self.current_style
	#print "current style 0x%02x" % b
	if 'link' in styles: b = b | 0x10
	else: b = b & ~0x10
	self.send_code(b)
	#print styles, "= 0x%02x" % b
	self.current_style = b
	
	
class Plugin(plugin_basicdoc.Plugin):
    name = 'RichReader'
    description = 'Assembles a RichReader-enhanced document.'

    links = [ (0, "doc-assembler", "doc-only-output") ]

    writerclass = RichReaderDocWriter

    def __init__(self, *a, **kw):
        apply(plugin_basicdoc.Plugin.__init__, (self,)+a, kw)

        #self._add_cli_option("h1_style", None, "h1-style",
        #                     "Heading 1 style",
        #                     vtype="STR")
        self._add_property("h1_style", "Heading 1 style")
        self.h1_style = "large bold left"

        self._add_property("h2_style", "Heading 2 style")
        self.h2_style = "normal bold italic underline left"

        self._add_property("h3_style", "Heading 2 style")
        self.h3_style = "normal bold underline left"
        
        self._add_property("h4_style", "Heading 2 style")
        self.h4_style = "normal bold left"
        
        self._add_property("h5_style", "Heading 2 style")
        self.h5_style = "normal underline left"
        
        self._add_property("h6_style", "Heading 2 style")
        self.h6_style = "normal italic left"
        
        self.api.register_task('mkrichreader', 'Convert to RichReader',
                               ['RichReader'])
