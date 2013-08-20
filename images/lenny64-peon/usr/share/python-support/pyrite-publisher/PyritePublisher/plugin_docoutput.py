#
#  $Id: plugin_docoutput.py,v 1.3 2002/07/15 21:40:28 rob Exp $
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

__version__ = '$Id: plugin_docoutput.py,v 1.3 2002/07/15 21:40:28 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import os

from dtkplugins import OutputPlugin
from doc_database import *

class Plugin(OutputPlugin):
    name = 'Doc'
    description = 'Outputs to a Doc database.'
    
    links = [ (0, "doc-output", "pdb-output"),
              (0, "doc-only-output", "pdb-output") ]
    # doc-only-output is for formats that will ever only work with
    # plain doc db (eg. richreader and teal); plain text formats and
    # things like HTML might one day be readable in zTXT or other formats
    # too, and thus can use doc-output.
    
    doc_version = 0
    
    def __init__(self, *a, **kw):
	OutputPlugin.__init__(self, *a, **kw)

	self._add_property('title', 'The document title')
	self._add_cli_option('title', 't', 'title',
			     'Set the document title',
			     vtype='STR')
	self.title = ''
	
	self._add_property('backup', 'Set the backup bit', boolean=1)
	self._add_cli_option('backup', 'b', 'backup',
			     "Set the document's backup bit",
			     boolean=1)
	self.backup = 0
			     
	self._add_property('category', 'The document category')
	self._add_cli_option('category', 'c', 'category',
			     "Set the document's category",
			     vtype="NUM", func=int)
	self.category = 0
	
	self._add_property('creator', 'The document creator')
	self._add_cli_option('creator', None, 'creator',
			     "Set the document's creator ID",
			     vtype="STR")
	self.creator = 'REAd'
	
	self._add_property('type', 'The document type')
	self._add_cli_option('type', None, 'type',
			     "Set the document's type",
			     vtype="STR")
	self.type = 'TEXt'

	self.doc = None

        self.api.register_task('raw2doc', 'Convert to Doc without reformatting',
                               ['RawText', 'Doc'])
        
    def open(self, chain, next, protocol, basename, *a, **kw):
	self.doc = DocWriteStream(next,
                                  self.title and self.title or basename,
				  self.creator, self.type, self.backup and 0x0008 or 0,
				  self.doc_version, self.category, 1)
	return self.doc

    def close(self):
	self.doc = None
            
