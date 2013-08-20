#
#  $Id: plugin_URLStream.py,v 1.1 2002/03/28 04:55:14 rob Exp $
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

__version__ = '$Id: plugin_URLStream.py,v 1.1 2002/03/28 04:55:14 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import sys, os, urlparse, mimetypes, re, urllib, tempfile

from dtkplugins import InputPlugin
from dtkmain import ConversionError

class Plugin(InputPlugin):
    name = 'URLStream'
    description = 'Gets input from a file or URL.'

    def __init__(self, *a, **kw):
	apply(InputPlugin.__init__, (self,)+a, kw)
	self.f = None

	self.generic_mimetypes = ["text/plain", "application/octet-stream"]

        self._temp_file_name = ''
        
    def handles_filename(self, fn):
	return 1
    
    def open_input(self, fn):
        # On win32, trying to urlopen a name with a drive-letter in it
        # fails, since it thinks the drive-letter is a protocol like
        # "http:" or "ftp:", so we handle these names separately.
        if sys.platform == 'win32' and re.match('^[a-zA-Z]:', fn):
            f = open(fn)
        else:
            f = urllib.urlopen(fn)  # raises IOError if fails

	n, ext = os.path.splitext(os.path.basename(fn))
	if ext == '.gz':
	    f = GzipFile(filename="", mode="rb", fileobj=f)
	    n, ext = os.path.splitext(n)

	self.f = f

        try:  # some type of URL don't have this
            mtype = f.info()["Content-Type"]
        except:
            mtype = "application/octet-stream"

	mtypes = [mtype]
	
	if mtype[:5] == "text/":
	    mtypes.append("application/octet-stream")

        # try guessing a type if it is text/plain or application/octet-stream
        if mtype in self.generic_mimetypes:
            gtype, genc = mimetypes.guess_type(n+ext)
            if gtype and gtype not in mtypes:
                mtypes.insert(0, gtype)

        # add types we can filter to
        mt0 = []
        for intype, outtype in self.api.input_filters.keys():
            if intype in mtypes and outtype not in mtypes:
                mt0.append(outtype)
        self._unfiltered_types = mtypes
        self._filtered_types = mt0
        mtypes = mtypes + mt0
        
        if not n: # handle urls with no path
            up = urlparse.urlparse(fn)
            n = up[1]

	return mtypes, os.path.basename(n)
    
    def close_input(self):
	if self.f is not None: self.f.close()
        if self._temp_file_name: os.unlink(self._temp_file_name)
	self.f = None

    def go(self, mimetype):
        if mimetype in self._filtered_types:
            for t in self._unfiltered_types:
                if self.api.input_filters.has_key((t,mimetype)):
                    filterprog = self.api.input_filters[(t,mimetype)]

                    tfn = tempfile.mktemp()
                    tf = open(tfn,'wb')
                    tf.write(self.f.read())
                    tf.close()
                    self._temp_file_name = tfn
                    
                    self.f = os.popen(filterprog % tfn, 'r')
                    break
                
	while 1:
	    l = self.f.readline()
	    if not l: break
	    self.next.feed(l)
	self.next.eof()
	
