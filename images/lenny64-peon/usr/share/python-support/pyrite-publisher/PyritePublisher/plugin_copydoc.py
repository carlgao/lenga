#
#  $Id: plugin_copydoc.py,v 1.3 2002/03/28 04:55:14 rob Exp $
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

__version__ = '$Id: plugin_copydoc.py,v 1.3 2002/03/28 04:55:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import dtkplugins, dtkmain

# This plugin is the first one to not fit into the usual 4-stage
# chain.  Its input interface is used by the pdbinput plugin to
# feed the contents of a doc directly, without reformatting but
# with metadata, through to a doc-output plugin.

class Plugin(dtkplugins.DTKPlugin):
    name = 'CopyDoc'
    description = 'Copies a doc database.'
    version = dtkmain.VERSION
    author = 'Rob Tillotson'
    author_email = 'rob@pyrite.org'
    
    links = [ (0, "DOC:raw", "doc-output") ]

    def open(self, chain, next, *a, **kw):
        # next is a docwritestream
        self.doc = next
        return self
    
    def close(self):
        self.doc.close()
        self.doc = None
        
    def feed_title(self, title):
        self.doc.name = title

    def feed_bookmark(self, s, pos):
        self.doc.bookmark(s, pos)

    def feed_annotation(self, text, t, pos):
        if self.doc.has_feature('annotate'):
            self.doc.annotate(text, t, pos)

    def feed(self, text):
        self.doc.write(text)

        
    
