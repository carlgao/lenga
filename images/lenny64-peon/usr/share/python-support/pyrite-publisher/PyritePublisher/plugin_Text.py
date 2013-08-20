#
#  $Id: plugin_Text.py,v 1.5 2002/02/05 12:06:14 rob Exp $
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

__version__ = '$Id: plugin_Text.py,v 1.5 2002/02/05 12:06:14 rob Exp $'

__copyright__ = 'Copyright 1999-2001 Rob Tillotson <rob@pyrite.org>'

import formatter, string, re

import dtkplugins

_re_indent = re.compile('^(\s+)')

class Plugin(dtkplugins.ParserPlugin):
    name = 'Text'
    description = 'Processes text input.'

    links = [ (0, "text/plain", "doc-assembler"),
	      (-10, "application/x-dtk-raw-stream", "doc-assembler") ]
    
    def __init__(self, *a, **kw):
	apply(dtkplugins.ParserPlugin.__init__, (self,)+a, kw)

        self.api.register_wildcard('*.txt', 'Text files')
        
	self.indented_paragraphs = 0
	self._add_property('indented_paragraphs', 'Use indentation to find paragraphs',
                           boolean=1)

	self._add_cli_option('indented_paragraphs', None, 'indented-paragraphs',
			     'Use indentation to find paragraphs',
			     boolean=1)

        self.bookmark_regexps = []
        self._add_property('bookmark_regexps', 'Regular expressions to bookmark', indexed=1)
        self._add_cli_option('bookmark_regexps', 'r', None,
                             'Regular expression to bookmark.',
                             vtype='REGEXP', multiple=1)
        

    def open(self, chain, next, *a, **kw):
	apply(dtkplugins.ParserPlugin.open, (self,chain,next)+a, kw)
	self.fmt = formatter.AbstractFormatter(next)
	self.in_para = 0
	self.use_indent = self.indented_paragraphs
	self.indent_level = None
	self.buf = ''

        self.bookmark_regexps = map(re.compile, self.bookmark_regexps)
	return self

    def feed(self, data):
	# in case we have multiple lines
	b = self.buf + data
	self.buf = ''
	if not b: return
	lines = string.split(b, '\n')
	self.buf = lines[-1]
	lines = lines[:-1]

	for l in map(lambda x: x + '\n', lines):
            re_matches = filter(None, map(lambda x,s=l: x.search(s), self.bookmark_regexps))
            if re_matches:
                g = re_matches[0].groups()
                if g: bm = g[0]
                else: bm = re_matches[0].group(0)
                self.fmt.writer.set_bookmark(bm)
                
	    if not string.strip(l):
		if self.in_para:
		    self.in_para = 0
		    self.fmt.end_paragraph(1)
	    else:
		if self.use_indent:
		    m = _re_indent.match(l)
		    if m:
			self.fmt.end_paragraph(1)
			
		self.in_para = 1
		self.fmt.add_flowing_data(l)
		    
