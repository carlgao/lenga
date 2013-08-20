#
#  $Id: doc_database.py,v 1.6 2002/03/26 21:34:33 rob Exp $
#
#  Copyright 1998-2001 Rob Tillotson <rob@pyrite.org>
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

__version__ = '$Id: doc_database.py,v 1.6 2002/03/26 21:34:33 rob Exp $'

__copyright__ = 'Copyright 1998-2001 Rob Tillotson <rob@pyrite.org>'


import string, operator, struct, time, sys

import prc

try:
    import _Doc
    _compress = _Doc.compress
    _uncompress = _Doc.uncompress
except:
    import doc_compress
    _compress = doc_compress.compress
    _uncompress = doc_compress.uncompress
    

def header_pack(version, spare, storylen, textrecs, recsize, position, sizes=[]):
    raw = struct.pack('>hhlhhl', version, spare, storylen, textrecs, recsize, position)
    for s in sizes:
	raw = raw + struct.pack('>h', s)
    return raw

def header_unpack(raw):
    fld = struct.unpack('>hhlhhl', raw[:16])
    raw = raw[16:]
    sizes = []
    while raw:
	r = raw[:2]
	raw = raw[2:]
	if len(r) != 2: break
	sizes.append(struct.unpack('>h',r)[0])

    return fld + (sizes,)

def bookmark_pack(text, pos):
    return struct.pack('>16sl', text[:15]+'\0', pos)

def bookmark_unpack(s):
    text, pos = struct.unpack('>16sl', s[:20])
    text = string.split(text,'\0',1)[0]
    return text, pos


class DocWriteStream:
    def __init__(self, filename, name, creator=None, type=None, flags=None,
		 version=None, category=0, compress=1, **kw):
	self.filename = filename
	self.name = name
	self.creator = creator
	self.type = type
	self.flags = flags
	self.version = version
	self.compress = compress
	self.category = category
	self.create_kw = kw

	self.appinfo = ''
	self.bookmarks = []
	self.records = []
	self.opened = 1
	self.buf = ''
	self.len = 0
	
    def has_feature(self, f):
        return None
    
    def set_appinfo(self, a=''):
	self.appinfo = a

    def bookmark(self, title, pos=None):
	if pos is None: pos = self.len
	self.bookmarks.append((title,pos))

    def annotate(self, text, title='', pos=None):
        pass
    
    def __output(self):
	while len(self.buf) >= 4096:
	    b = self.buf[:4096]
	    self.buf = self.buf[4096:]

	    if self.compress:
		self.records.append(_compress(b))
	    else:
		self.records.append(b)
	    
    def write(self, data):
	self.buf = self.buf + data
	self.len = self.len + len(data)
	self.__output()

    def writelines(self, list):
	for l in list: self.write(l)

    def close(self):
	self.__output()
	if self.buf:
	    if self.compress:
		self.records.append(_compress(self.buf))
	    else:
		self.records.append(self.buf)

        if type(self.filename) == type(''):
            db = prc.File(self.filename, read=0, write=1,
                          info={'name': self.name,
                           'creator': self.creator,
                           'type': self.type,
                           'version': self.version,
                           # flags?
                           })
        else:
            db = self.filename # assume it is a prc object if not a string
            db.updateDBInfo({'name': self.name,
                             'creator': self.creator,
                             'type': self.type,
                             'version': self.version,
                             })
	# header
	db.setRecord(0x40, 0x6f8000, self.category,
		     header_pack(2, 0, self.len, len(self.records), 4096, 0))

	uid = 0x6f8001
	for r in self.records:
	    db.setRecord(0x40, uid, 0, r)
	    uid = uid + 1

	if len(self.bookmarks):
	    for t, p in self.bookmarks:
		db.setRecord(0x40, uid, 0, bookmark_pack(t,p))
		uid = uid + 1

	if self.appinfo:
	    db.setAppBlock(self.appinfo)

	self.opened = 0
	db.close()
	

class DocReadStream:
    def __init__(self, file=None, db=None):
	if db is not None:
	    self.db = db
	else:
	    self.db = prc.File(file,read=1,write=0)
	self.rec = 0
	self.buf = ''

	raw, idx, id, attr, category = self.db.getRecord(0)

	self.category = category
	(self.version, self.spare, self.storylen,
	 self.textrecs, self.recsize, self.position,
	 self.sizes) = header_unpack(raw)

    def __next(self):
	if self.rec >= self.textrecs:
	    return None
	else:
	    self.rec = self.rec + 1
	    raw, idx, id, attr, category = self.db.getRecord(self.rec)
	    if self.version >= 2:
		r = _uncompress(raw)
	    else:
		r = raw
	    self.buf = self.buf + r
	    return r

    def read(self, nbytes=0):
	if not self.buf:
	    if self.__next() is None:
		return ''

	if nbytes:
	    e = self.buf[:nbytes]
	    self.buf = self.buf[nbytes:]
	    return e
	else:
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
	return (self.rec * self.recsize) - len(self.buf)

    def seek(self, pos, whence=0):
	if whence == 1: pos = self.tell() + pos
	elif whence == 2: pos = self.storylen + pos

	if pos >= self.storylen:
	    pos = self.storylen

	self.rec = int(pos / self.recsize) + 1
	p = pos % self.recsize
	raw, idx, id, attr, category = self.db.getRecord(self.rec)
	if self.version >= 2: self.buf = _uncompress(raw)
	else: self.buf = raw

    def close(self):
	self.db.close()
	self.rec = 0
	self.buf = ''

    def has_feature(self, f):
        return None
    
    def get_bookmarks(self):
        l = []
        r = self.textrecs+1
        end = self.db.getRecords()
        for x in range(r, end):
            raw, idx, id, attr, category = self.db.getRecord(x)
            text, pos = bookmark_unpack(raw)
            l.append((pos, text))
        l.sort()
        return l
    
    def __getattr__(self, k):
        if k == 'title': return self.db.getDBInfo()['name']
        elif k == 'bookmarks': return self.get_bookmarks()
        else: raise AttributeError, k

    
