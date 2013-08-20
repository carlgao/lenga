#
#  $Id: plugin_TaggedText.py,v 1.7 2002/02/05 12:06:14 rob Exp $
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

__version__ = '$Id: plugin_TaggedText.py,v 1.7 2002/02/05 12:06:14 rob Exp $'

__copyright__ = 'Copyright 1999-2001 Rob Tillotson <rob@pyrite.org>'

import formatter, string, re

import dtkplugins

class Plugin(dtkplugins.ParserPlugin):
    name = 'TaggedText'
    description = 'Processes text input with Pyrite Publisher tags.'

    links = [ (0, "application/x-dtk-tagged-text", "doc-assembler"),
	      (-10, "text/plain", "doc-assembler"),
	      (-10, "application/x-dtk-raw-stream", "doc-assembler") ]
    
    def __init__(self, *a, **kw):
	apply(dtkplugins.ParserPlugin.__init__, (self,)+a, kw)

	self.tag_prefix = '.'
	self.case_fold_tags = 0
	self.tag_regexp = ''
	self._add_property('tag_prefix', 'Tag prefix')
	self._add_property('case_fold_tags', 'Fold tags to lower case', boolean=1)
	self._add_property('tag_regexp', 'Regular expression to match tags')
	
	self._add_cli_option('tag_prefix', None, 'tag-prefix',
			     "Tag prefix",
			     vtype='STR')
	self._add_cli_option('case_fold_tags', None, 'case-fold-tags',
			     "Fold tags to lower case",
			     boolean=1)
	self._add_cli_option('tag_regexp', None, 'tag-regexp',
			     "Regular expression to match tags",
			     vtype='RE')

	self.bookmark_regexps = []
        self._add_property('bookmark_regexps', 'Regular expressions to bookmark', indexed=1)
        self._add_cli_option('bookmark_regexps', 'r', None,
                             'Regular expression to bookmark.',
                             vtype='REGEXP', multiple=1)
        
    def open(self, chain, next, *a, **kw):
	apply(dtkplugins.ParserPlugin.open, (self,chain,next)+a, kw)
	self.fmt = formatter.AbstractFormatter(next)
	self.in_para = 0
	self.tapi = TagAPI(self.tag_prefix,
			   self.case_fold_tags,
			   self.tag_regexp)  #####
	self.buf = ''
        self.bookmark_regexps = map(re.compile, self.bookmark_regexps)
	return self
	
    def feed(self, data):
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
                
	    # this is kind of screwy.  no, this whole thing is kind of screwy.
	    m = self.tapi.match(l)
	    if m:
		try:
		    l = self.tapi.process(m, self.fmt, self.next)
		except RuntimeError:
		    pass
		if not l: continue

            if self.tapi.capturing:
                self.tapi.capture_text(l)
	    elif self.tapi.verbatim:
		self.fmt.add_literal_data(l)
	    else:
		if not string.strip(l):
		    if self.in_para:
			self.in_para = 0
			self.fmt.end_paragraph(1)
		else:
		    self.in_para = 1
		    self.fmt.add_flowing_data(l)
		    

class TagAPI:
    def __init__(self, prefix='.', case_fold=0, tagregex=None, verbatim=0):
	if not tagregex:
	    self.tagregex = "^%(prefix)s\s*(?P<tag>[a-zA-Z0-9/_]+)(?:\s*(?P<arg>.*)\s*)?"
	self.tagprefix = prefix
	self.case_fold = case_fold

	self.tagre = re.compile(self.tagregex % {'prefix': re.escape(prefix)})
	self.verbatim = verbatim

        self.capturing = 0
        self.cap_buf = ''

        self.tag_args = []  # stack for tags to use to temporarily store stuff
        
    def start_capture(self):
        self.cap_buf = ''
        self.capturing = 1

    def end_capture(self):
        self.capturing = 0
        return self.cap_buf

    def capture_text(self, text):
        self.cap_buf = self.cap_buf + text
        
    def match(self, l):
	return self.tagre.match(string.rstrip(l))

    def process(self, m, fmt, w):
	tag, arg = m.group('tag','arg')
	if self.case_fold: tag = string.upper(tag)
        if tag and tag[0] != '/': meth = 'tag_' + tag
        else: meth = 'end_' + tag[1:]
	if hasattr(self, meth):
	    return apply(getattr(self, meth), (arg, fmt, w))
	elif hasattr(self, 'tag'):
	    return self.tag(tag, arg, fmt, w)

    def tag_TITLE(self, arg, fmt, w):
	w.set_title(arg)
    def tag_BOOKMARK(self, arg, fmt, w):
	w.set_bookmark(arg)
    tag_BM = tag_BOOKMARK
    def tag_H1(self, arg, fmt, w):
	fmt.end_paragraph(1)
	w.send_heading(arg, 1)
    def tag_H2(self, arg, fmt, w):
	fmt.end_paragraph(1)
	w.send_heading(arg, 2)
    def tag_H3(self, arg, fmt, w):
	fmt.end_paragraph(1)
	w.send_heading(arg, 3)
    def tag_H4(self, arg, fmt, w):
	fmt.end_paragraph(1)
	w.send_heading(arg, 4)
    def tag_H5(self, arg, fmt, w):
	fmt.end_paragraph(1)
	w.send_heading(arg, 5)
    def tag_H6(self, arg, fmt, w):
	fmt.end_paragraph(1)
	w.send_heading(arg, 6)
    def tag_ANNOTATION(self, arg, fmt, w):
        self.tag_args.append(arg)
        self.start_capture()
    def end_ANNOTATION(self, arg, fmt, w):
        t = self.tag_args.pop()
        c = self.end_capture()
        # fix paragraphs in the annotation
        l = re.split('[ \t]*\n[ \t]*\n', c)
        l = map(lambda x: string.strip(string.join(string.split(x))), l)
        c = string.join(l, '\n\n')
        w.set_annotation(c, t)
    tag_ANN = tag_ANNOTATION
    end_ANN = end_ANNOTATION
    def tag_PRE(self, *a, **kw):
	self.verbatim = 1
    def end_PRE(self, *a, **kw):
        self.verbatim = 0
    def tag(self, tag, arg, fmt, w):
        raise RuntimeError, 'invalid tag %s' % tag
    def tag_HR(self, arg, fmt, w):
	apply(w.send_hor_rule, (), {'break':'both'})
	
