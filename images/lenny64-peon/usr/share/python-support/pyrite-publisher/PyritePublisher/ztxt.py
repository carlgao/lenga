#
#  $Id: ztxt.py,v 1.5 2002/03/26 21:34:33 rob Exp $
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
"""Read and write Gutenpalm zTXT documents.

Gutenpalm is a free document reader for Palm Computing Platform
handhelds, which uses its own document format that uses zlib to
provide greater compression than the standard Doc format used by most
other Palm document readers.  This module provides objects which allow
reading and writing of zTXT documents using a file-like interface.

The zTXTWriteStream object allows creation of a new zTXT document
database.  Because of restrictions in the Palm database format, it is
not possible to append to an existing database, and the entire
contents of the database must be held in memory in the zTXTWriteStream
instance until the stream is closed.  Also note that the
zTXTWriteStream MUST be explicitly saved by calling its close()
method; if it is deleted by the Python garbage collector, it may not
be written to the filesystem.

The zTXTReadStream object allows reading of an existing zTXT document
database.  If the document was compressed in random access mode, it is
seekable; otherwise it is only readable sequentially and using the
tell() or seek() methods will raise IOError.
"""

__version__ = '$Id: ztxt.py,v 1.5 2002/03/26 21:34:33 rob Exp $'

__author__ = 'Rob Tillotson <rob@pyrite.org>'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import string, struct, zlib

import prc

def trim_null(s):
    return string.split(s, '\0', 1)[0]
    
class zTXTWriteStream:
    """A writable stream that produces a zTXT document database.
    """
    def __init__(self, filename, name, random_access=1, stored_prefs=0,
                 creator='GPlm', type='zTXT'):
        self.filename = filename
        self.name = name
        self.random_access = random_access
        self.stored_prefs = stored_prefs
        self.creator = creator
        self.type = type

        self.appinfo = ''
        self.bookmarks = []
        self.annotations = []
        self.data = []
        self.opened = 1
        self.buf = ''
        self.len = 0

        self.compressobj = zlib.compressobj(9)

    def has_feature(self, f):
        """Test whether the stream has a particular feature.
        This is used to differentiate this stream from others that are
        interface-compatible.
        """
        if f in ['annotate']:
            return 1
        
    def bookmark(self, title, pos=None):
        """Set a bookmark.
        If the second argument is None, the bookmark will be placed at
        the current position in the document.
        """
        if pos is None: pos = self.len
        self.bookmarks.append((pos,title))

    def annotate(self, text, title='', pos=None):
        """Set an annotation.
        If the third argument is None, the annotation will be placed
        at the current position in the document.
        """
        if pos is None: pos = self.len
        self.annotations.append((pos, title, text))
        
    def __output(self, flush=0):
        while (flush and self.buf) or len(self.buf) >= 8192:
            b = self.buf[:8192]
            self.buf = self.buf[8192:]

            cdata = self.compressobj.compress(b)
            if self.random_access:
                cdata = cdata + self.compressobj.flush(zlib.Z_FULL_FLUSH)

            self.data.append(cdata)

    def write(self, data):
	self.buf = self.buf + data
	self.len = self.len + len(data)
	self.__output()

    def writelines(self, list):
	for l in list: self.write(l)

    def close(self):
        self.__output(1)

        if not self.random_access: # reblock into 8k chunks
            s = string.join(self.data,'') + self.compressobj.flush(zlib.Z_FINISH)
            self.data = []
            while s:
                self.data.append(s[:8192])
                s = s[8192:]

        if type(self.filename) == type(''):
            db = prc.File(self.filename, read=0, write=1,
                          info = {'name': self.name,
                                  'creator': self.creator,
                                  'type': self.type,
                                  'version': 296,
                                  })
        else:
            db = self.filename
            db.updateDBInfo({'name': self.name,
                             'creator': self.creator,
                             'type': self.type,
                             'version': 296,
                             })
            
        if len(self.bookmarks): bookmark_index = len(self.data)+1
        else: bookmark_index = 0

        if len(self.annotations):
            annotation_index = len(self.data)+1
            if len(self.bookmarks): annotation_index = annotation_index + 1
        else:
            annotation_index = 0
        
        hdr = struct.pack('>HHLHHHHHBxH11x',
                          0x0128, # version 1.40
                          len(self.data), self.len, 8192,
                          len(self.bookmarks), bookmark_index,
                          len(self.annotations), annotation_index,
                          self.random_access, self.stored_prefs)

        db.setRecord(0x40, 0x424200, 0, hdr)
        
        uid = 0x424201
        for r in self.data:
            db.setRecord(0x40, uid, 0, r)
            uid = uid + 1

        if len(self.bookmarks):
            self.bookmarks.sort()
            brec = ''
            for pos, title in self.bookmarks:
                brec = brec + struct.pack('>L20s', pos, title[:19]+'\0')
            db.setRecord(0x40, uid, 0, brec)
            uid = uid + 1

        if len(self.annotations):
            self.annotations.sort()
            brec = ''
            for pos, title, text in self.annotations:
                brec = brec + struct.pack('>L20s', pos, title[:19]+'\0')
            db.setRecord(0x40, uid, 0, brec)
            uid = uid + 1
            
            for pos, title, text in self.annotations:
                db.setRecord(0x40, uid, 0, (text[:4095]+'\0'))
                uid = uid + 1

        if self.appinfo:
            db.setAppBlock(self.appinfo)

        self.opened = 0
        db.close()


class zTXTReadStream:
    """A file-like interface to read a zTXT document.
    """
    def __init__(self, file=None, db=None):
        if db is not None:
            self.db = db
        else:
            self.db = prc.File(file,read=1,write=0)
        self.rec = 0
        self.buf = ''

        raw, idx, id, attr, category = self.db.getRecord(0)
        (self.version, self.numrecs, self.length, self.recsize,
         self.num_bookmarks, self.bookmark_index,
         self.num_annotations, self.annotation_index,
         self.random_access, self.stored_prefs) = struct.unpack('>HHLHHHHHBxH11x', raw)

        # if it's non random_access, it isn't seekable.
        self.decompressobj = zlib.decompressobj()
        
    def __next(self):
        if self.rec >= self.numrecs:
            return None
        else:
            self.rec = self.rec + 1
            raw, idx, id, attr, category = self.db.getRecord(self.rec)
            self.buf = self.buf + self.decompressobj.decompress(raw)
            return self.buf
        
    def read(self, nbytes=0):
        if not self.buf:
            if self.__next() is None:
                return ''

        if nbytes:
            e = self.buf[:nbytes]
            self.buf = self.buf[nbytes:]
            return e
        else:
            # this should really read the whole file
            e = self.buf
            self.buf = ''
            return e

    def readline(self):
        while not '\n' in self.buf:
            if self.__next() is None:
                b = self.buf
                self.buf = ''
                return b

        j = string.find(self.buf, '\n')
        e = self.buf[:j+1]
        self.buf = self.buf[j+1:]
        return e

    def readlines(self):
        l = []
        while 1:
            m = self.readline()
            if not m: break
            l.append(m)
        return l

    def tell(self):
        if not self.random_access:
            raise IOError, 'not seekable'
        return (self.rec * self.recsize) - len(self.buf)

    def seek(self, pos, whence=0):
        if not self.random_access:
            raise IOError, 'not seekable'
        if whence == 1: pos = self.tell() + pos
        elif whence == 2: pos = self.length + pos

        if pos >= self.length: pos = self.length

        self.rec = int(pos / self.recsize) + 1
        p = pos % self.recsize
        raw, idx, id, attr, category = self.db.getRecord(self.rec)
        self.buf = zlib.decompressobj.decompress(raw)

    def close(self):
        self.db.close()
        self.rec = 0
        self.buf = ''

    def has_feature(self, f):
        if f in ['annotate']: return 1
        
    def get_bookmarks(self):
        l = []
        raw = self.db.getRecord(self.bookmark_index)[0]
        for x in range(0, self.num_bookmarks):
            pos, text = struct.unpack('>L20s', raw[:24])
            text = trim_null(text)
            l.append((pos, text))
            raw = raw[24:]
        l.sort()
        return l
    
    def get_annotations(self):
        l = []
        annrec = self.db.getRecord(self.annotation_index)[0]
        for x in range(0, self.num_annotations):
            pos, title = struct.unpack('>L20s', annrec[:24])
            title = trim_null(title)
            annrec = annrec[24:]
            text = trim_null(self.db.getRecord(self.annotation_index + x + 1)[0])
            l.append((pos, title, text))
        l.sort()
        return l

    def __getattr__(self, k):
        if k == 'title': return self.db.getDBInfo()['name']
        elif k == 'bookmarks': return self.get_bookmarks()
        elif k == 'annotations': return self.get_annotations()
        else: raise AttributeError, k
        
if __name__ == '__main__':
    import sys
    fn = sys.argv[1]

    s = zTXTReadStream(fn)
    print string.join(s.readlines(), '')
    
    
