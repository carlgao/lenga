#
#  $Id: plugin_pdbinput.py,v 1.3 2002/07/15 21:40:28 rob Exp $
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

__version__ = '$Id: plugin_pdbinput.py,v 1.3 2002/07/15 21:40:28 rob Exp $'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import os, string, urllib, sys, re

import dtkplugins, prc, doc_database, ztxt

try:
    import _Doc
    _compress = _Doc.compress
    _uncompress = _Doc.uncompress
except:
    import doc_compress
    _compress = doc_compress.compress
    _uncompress = doc_compress.uncompress
    

class Plugin(dtkplugins.InputPlugin):
    name = 'PDBInput'
    description = 'Input from a pdb/prc file.'

    def __init__(self, *a, **kw):
	apply(dtkplugins.InputPlugin.__init__, (self,)+a, kw)
        self.api.register_wildcard('*.pdb', 'Palm databases')
        self.api.register_wildcard('*.prc', 'Palm resources')
        
	self.pdb = None
	self.is_doc = 0
	
    def handles_filename(self, fn):
	n, e = os.path.splitext(fn)
	e = string.lower(e)
	if e == '.prc' or e == '.pdb':
	    return 10

    # The way this will work is that palm database types will be
    # represented by special MIME types like "PDB:<creator><type>"
    # and the database will be fed in sequential order as records.
    #
    # This has special handling for Doc databases, because they
    # will be handled as if they contained some other format of
    # text; i.e. they can have multiple mime types, depending on
    # their content.
    def open_input(self, fn):
        # Win32 hack, see the basic input plugin for why.
        if sys.platform == 'win32' and re.match('^[a-zA-Z]:', fn):
            f = open(fn)
        else:
            f = urllib.urlopen(fn)
	# no automatic ungzipping here, i guess

	# load the entire prc, too bad there isn't a better way to do this
	self.pdb = prc.File(f)

	# doc.
        creator = self.pdb.info['creator']
        type = self.pdb.info['type']
	mtypes = ['PDB:'+creator+'/'+type]
	if (type == 'TEXt' and creator in ('REAd', 'TLDc')) or \
           (type == 'zTXT' and creator == 'GPlm'):
	    mtypes = self.open_doc(type) + mtypes
	
	return mtypes, os.path.basename(fn)

    def close_input(self):
	self.pdb = None
	self.is_doc = 0
	
    def open_doc(self, type):
	self.is_doc = type
	# for now, treat all docs as application/octet-stream
	# later check the first record to try to ascertain a doctype
	#return ["DOC:raw", "application/octet-stream"]
	return ["text/plain", "DOC:raw"]
	
    def go(self, mimetype):
	if self.is_doc:
            if self.is_doc == 'zTXT':
                stream = ztxt.zTXTReadStream(db=self.pdb)
            else:
                stream = doc_database.DocReadStream(db=self.pdb)

            while 1:
                l = stream.read()
                if not l: break
                self.next.feed(l)

            if mimetype == 'DOC:raw':
                self.next.feed_title(self.pdb.info['name'])
                for pos, text in stream.bookmarks:
                    self.next.feed_bookmark(text, pos)
                if stream.has_feature('annotate'):
                    for pos, title, text in stream.annotations:
                        self.next.feed_annotation(text, title, pos)
                
	    stream.close()
	    
	else:
	    # totally untested, probably need to redesign
	    self.next.feed_pdb_header(self.pdb.info)
	    self.next.feed_pdb_appinfo(self.pdb.appblock)
	    self.next.feed_pdb_sortinfo(self.pdb.sortblock)
	    if self.pdb.info['flagResource']:
		for i in range(0,self.pdb.getRecords()):
		    apply(self.next.feed_pdb_resource, self.pdb.getResource(i))
	    else:
		for i in range(0,self.pdb.getRecords()):
		    apply(self.next.feed_pdb_record, self.pdb.getRecord(i))
	    self.next.feed_pdb_end();
	
	    
    
