#
#  $Id: plugin_HTML.py,v 1.10 2002/07/15 21:40:28 rob Exp $
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

__version__ = '$Id: plugin_HTML.py,v 1.10 2002/07/15 21:40:28 rob Exp $'

__copyright__ = 'Copyright 1999-2001 Rob Tillotson <rob@pyrite.org>'

import formatter, htmllib, string, urlparse, os

import dtkplugins

class Plugin(dtkplugins.ParserPlugin):
    name = 'HTML'
    description = 'Processes HTML input.'

    links = [ (0, "text/html", "doc-assembler"),
	      (-10, "text/plain", "doc-assembler"),
	      (-10, "application/x-dtk-raw-stream", "doc-assembler"),
              (0, "MULTIPART:web", "doc-assembler")]
    
    def __init__(self, *a, **kw):
	apply(dtkplugins.ParserPlugin.__init__, (self,)+a, kw)

        self.api.register_wildcard('*.htm', 'HTML files')
        self.api.register_wildcard('*.html', 'HTML files')
        
	self._add_cli_option('footnote_links', None, 'footnote-links',
			     'Mark and footnote links',
			     boolean=1)
	self._add_property('footnote_links', 'Mark and footnote links', boolean=1)
	self.footnote_links = 0

	self._add_cli_option('bookmark_anchors', None, 'bookmark-anchors',
			     'Bookmark local anchor targets',
			     boolean=1)
	self._add_property('bookmark_anchors', 'Do not bookmark local anchor targets',
                           boolean=1)
	self.bookmark_anchors = 0

        self._add_cli_option('annotate_links', None, 'annotate-links',
                             'Mark and annotate links',
                             boolean=1)
	self._add_property('annotate_links', 'Mark and annotate links', boolean=1)
	self.annotate_links = 0        
        
        self._add_cli_option('bookmark_headers', None, 'bookmark-headers',
                             'Levels of headers to bookmark',
                             vtype="STR")
        self._add_property('bookmark_headers', 'Levels of headers to bookmark')
        self.bookmark_headers = ''
        

    def open(self, chain, next, *a, **kw):
	apply(dtkplugins.ParserPlugin.open, (self,chain,next)+a, kw)
	self.fmt = formatter.AbstractFormatter(next)
	self.parser = DocHTMLParser(self.fmt)
        self.copyProperties(self.parser)
	self.ttbl = string.maketrans('','')
	self.buf = ''
	return self
    
    def feed(self, data):
	l = string.translate(data, self.ttbl, '\r')
	self.parser.feed(l)

    def eof(self):
	if self.parser.anchorlist and self.footnote_links:
            self.fmt.end_paragraph(1)
            self.fmt.add_hor_rule()
            self.next.set_bookmark('%s Links' % chr(187))
            self.next.send_heading('Links:', 3)
            for x in range(0, len(self.parser.anchorlist)):
                self.fmt.add_label_data('[1] ', x+1)
                self.fmt.add_flowing_data(self.parser.anchorlist[x])
                self.fmt.add_line_break()

    def process_multipart_web(self, pages):
        # for now, this just concatenates the pages together with
        # a bookmark in between
        # we already have a formatter etc., but we will be making
        # a new parser for each one.
        addsplit = 0
        for url, mtype, filename, extra in pages:
            if mtype != 'text/html':
                print "Skipping", url, "because it isn't html"
                continue
            if addsplit:
                self.fmt.end_paragraph(1)
                self.fmt.add_hor_rule()
            print "Writing", url
            self.next.set_bookmark(os.path.basename(urlparse.urlparse(url)[2])) # get title for this instead?
            parser = DocHTMLParser(self.fmt)
            self.copyProperties(parser)
            data = open(filename).read()
            parser.feed(string.translate(data, self.ttbl, '\r'))
            addsplit = 1
            # handle footnote_links etc.
            
        
        

class DocHTMLParser(htmllib.HTMLParser):
    """A HTML parser with some support for Doc-format e-texts."""
    def __init__(self, *a, **kw):
	apply(htmllib.HTMLParser.__init__, (self,)+a, kw)
	self.writer = self.formatter.writer
	self.tcol = 0
        self.capture_data = None
        
    def end_title(self):
	htmllib.HTMLParser.end_title(self)
	self.writer.set_title(self.title)
#	if not self.writer.has_title():
#	    self.writer.set_title(self.title)

    # entities
    from entitydefs import entitydefs

    # capturing.  this is like save_bgn/save_end in the superclass,
    # but doesn't eat the data in the process.
    def handle_data(self, data):
        if self.capture_data is not None:
            self.capture_data = self.capture_data + data
        htmllib.HTMLParser.handle_data(self, data)

    def capture_bgn(self):
        self.capture_data = ''

    def capture_end(self):
        d = self.capture_data
        self.capture_data = None
        if not self.nofill:
            data = string.join(string.split(d))
        return data
    
    # headings
    def start_h1(self, attr):
	self.save_bgn()

    def end_h1(self):
	text = self.save_end()
	self.formatter.end_paragraph(1)
        if '1' in self.bookmark_headers:
            self.writer.set_bookmark(text)
	self.writer.send_heading(text, 1)

    def start_h2(self, attr):
	self.save_bgn()

    def end_h2(self):
	text = self.save_end()
	self.formatter.end_paragraph(1)
        if '2' in self.bookmark_headers:
            self.writer.set_bookmark(text)
	self.writer.send_heading(text, 2)

    def start_h3(self, attr):
	self.save_bgn()

    def end_h3(self):
	text = self.save_end()
	self.formatter.end_paragraph(1)
        if '3' in self.bookmark_headers:
            self.writer.set_bookmark(text)
	self.writer.send_heading(text, 3)

    def start_h4(self, attr):
	self.save_bgn()

    def end_h4(self):
	text = self.save_end()
	self.formatter.end_paragraph(1)
        if '4' in self.bookmark_headers:
            self.writer.set_bookmark(text)
	self.writer.send_heading(text, 4)

    def start_h5(self, attr):
	self.save_bgn()

    def end_h5(self):
	text = self.save_end()
	self.formatter.end_paragraph(1)
        if '5' in self.bookmark_headers:
            self.writer.set_bookmark(text)
	self.writer.send_heading(text, 5)

    def start_h6(self, attr):
	self.save_bgn()

    def end_h6(self):
	text = self.save_end()
	self.formatter.end_paragraph(1)
        if '6' in self.bookmark_headers:
            self.writer.set_bookmark(text)
	self.writer.send_heading(text, 6)

    # anchors.
    def anchor_bgn(self, href, name, type):
	if name and self.bookmark_anchors:
	    if name[0] == '#': name = name[1:]
	    self.writer.set_bookmark(name)
	    
	#if self.writer.has_option('teal-links'):
	#    if name:
	#	if name[0] == '#': name = name[1:]
	#	self.writer.send_raw_tag('LABEL',{'NAME':'"%s"' % name})
	#    if href and href[0] == '#':
	#	self.writer.send_raw_tag('LINK',{'TEXT':'"%s"' % (chr(187)*2),
	#					 'FONT':'0',
	#					 'TAG':'"%s"' % href[1:],
	#					 'STYLE':'UNDERLINE'})
	#    elif href and not self.writer.has_option('no-links'):
	#	self.anchor = href
	#	self.anchorlist.append(href)
	elif href and href[0] != '#' and (self.footnote_links or self.annotate_links):
	    self.anchor = href
	    self.anchorlist.append(href)

        #self.capture_bgn()
	self.formatter.push_style('link')
        
    def anchor_end(self):
	self.formatter.pop_style()
        #title = self.capture_end()
        if self.anchor:
            if self.annotate_links:
                self.writer.set_annotation(self.anchor,
                                           'Link #%s' % len(self.anchorlist))
            if (self.footnote_links or self.annotate_links):
                self.writer.mark_footnote(len(self.anchorlist))
            self.anchor = None
                
	
    # now, let's see what we can do about tables.
    # the simplest thing to do is to treat each table row as a separate line;
    def do_tr(self, attrs):
	self.tcol = 0
	self.formatter.end_paragraph(0)

    def do_td(self, attrs):
	if self.tcol: self.formatter.add_flowing_data(' ')
	self.tcol = self.tcol+1

    def start_table(self, attrs):
	pass
    
    def end_table(self):
	self.formatter.end_paragraph(1)

    #-- Lists, mostly cribbed from htmllib.
    def start_ul(self, attrs):
	type = 'disc'
	for a, v in attrs:
	    if a == 'type': type = v
	if type == 'square': label = chr(0x8d)
	elif type == 'circle': label = 'o'
	else: label = chr(0x95)
	self.formatter.end_paragraph(not self.list_stack)
	self.formatter.push_margin('ul')
	self.list_stack.append(['ul', label, 0])

    def do_li(self, attrs):
	self.formatter.end_paragraph(0)
	if self.list_stack:
	    [dummy, label, counter] = top = self.list_stack[-1]
	    top[2] = counter = counter+1
	else:
	    label, counter = chr(0x95), 0
	self.formatter.add_label_data(label, counter)

    # --- elements we want to discard entirely
    def start_style(self, attr):
        self.save_bgn()
    def end_style(self):
        self.save_end()

    
