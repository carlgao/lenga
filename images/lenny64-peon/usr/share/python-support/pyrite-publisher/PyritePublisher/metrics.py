#
#  $Id: metrics.py,v 1.1 2001/03/29 21:15:44 rob Exp $
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

__version__ = '$Id: metrics.py,v 1.1 2001/03/29 21:15:44 rob Exp $'

__copyright__ = 'Copyright 1998-2001 Rob Tillotson <rob@pyrite.org>'

import operator, string

metrics_normal = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x00 - 0x0f (controls)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x10 - 0x1f (controls)
    3, 2, 4, 8, 6, 7, 6, 2, 4, 4, 6, 6, 3, 4, 2, 5,  # 0x20 - 0x2f (spc/punct)
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 2, 3, 6, 6, 6, 5,  # 0x30 - 0x3f (num/punct)
    8, 5, 5, 5, 6, 4, 4, 6, 6, 2, 4, 6, 5, 8, 6, 7,  # 0x40 - 0x4f (@/A-O)
    5, 7, 5, 5, 6, 6, 6, 8, 6, 6, 6, 3, 5, 3, 6, 5,  # 0x50 - 0x5f (P-Z/punct)
    3, 5, 5, 4, 5, 5, 4, 5, 5, 2, 3, 5, 2, 8, 5, 5,  # 0x60 - 0x6f (bquote/a-o)
    5, 5, 4, 4, 4, 5, 5, 6, 6, 6, 4, 4, 2, 4, 7, 0,  # 0x70 - 0x7f (p-z/punct)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x80 - 0x8f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x90 - 0x9f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xa0 - 0xaf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xb0 - 0xbf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xc0 - 0xcf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xd0 - 0xdf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xe0 - 0xef
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xf0 - 0xff
    ]

metrics_bold = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x00 - 0x0f (controls)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x10 - 0x1f (controls)
    3, 3, 6,10, 6,13, 9, 3, 5, 5, 6, 6, 3, 5, 3, 6,  # 0x20 - 0x2f (spc/punct)
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 3, 3, 6, 6, 6, 6,  # 0x30 - 0x3f (num/punct)
   10, 7, 7, 6, 7, 5, 5, 8, 8, 3, 5, 7, 6,10, 7, 8,  # 0x40 - 0x4f (@/A-O)
    7, 8, 8, 6, 7, 7, 8,11, 7, 7, 7, 4, 6, 4, 6, 6,  # 0x50 - 0x5f (P-Z/punct)
    4, 5, 6, 5, 6, 6, 5, 6, 6, 3, 4, 6, 3, 9, 6, 6,  # 0x60 - 0x6f (bquote/a-o)
    6, 6, 5, 5, 6, 6, 6, 9, 6, 6, 5, 5, 3, 5, 7, 0,  # 0x70 - 0x7f (p-z/punct)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x80 - 0x8f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x90 - 0x9f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xa0 - 0xaf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xb0 - 0xbf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xc0 - 0xcf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xd0 - 0xdf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xe0 - 0xef
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xf0 - 0xff
    ]

metrics_big = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x00 - 0x0f (controls)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x10 - 0x1f (controls)
    5, 2, 4, 9, 6,11, 8, 2, 4, 4, 6, 8, 3, 4, 2, 5,  # 0x20 - 0x2f (spc/punct)
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 2, 3, 7, 7, 7, 5,  # 0x30 - 0x3f (num/punct)
   11, 9, 6, 7, 7, 6, 6, 8, 7, 3, 4, 7, 5,10, 7, 8,  # 0x40 - 0x4f (@/A-O)
    6, 8, 6, 5, 6, 7, 7,11, 7, 6, 5, 3, 5, 3, 6, 6,  # 0x50 - 0x5f (P-Z/punct)
    3, 6, 7, 6, 7, 7, 4, 7, 6, 3, 3, 6, 2,10, 7, 7,  # 0x60 - 0x6f (bquote/a-o)
    7, 7, 4, 5, 4, 7, 6,10, 6, 7, 6, 4, 2, 4, 7, 0,  # 0x70 - 0x7f (p-z/punct)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x80 - 0x8f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x90 - 0x9f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xa0 - 0xaf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xb0 - 0xbf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xc0 - 0xcf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xd0 - 0xdf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xe0 - 0xef
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xf0 - 0xff
    ]

metrics_template = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x00 - 0x0f (controls)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x10 - 0x1f (controls)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x20 - 0x2f (spc/punct)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x30 - 0x3f (num/punct)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x40 - 0x4f (@/A-O)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x50 - 0x5f (P-Z/punct)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x60 - 0x6f (bquote/a-o)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x70 - 0x7f (p-z/punct)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x80 - 0x8f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0x90 - 0x9f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xa0 - 0xaf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xb0 - 0xbf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xc0 - 0xcf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xd0 - 0xdf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xe0 - 0xef
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 0xf0 - 0xff
    ]

metrics = {
    0: metrics_normal,
    1: metrics_bold,
    2: metrics_big
    }

def width(s, font=0):
    if font == 'p': # profont (fixed width, used in AportisDoc)
	return 6 * len(s)
    
    mt = metrics.get(font, metrics_normal)
    return reduce(operator.add,
		  map(lambda x, m=mt: m[x],
		      map(ord, s)),
		  0)

def wordwrap(s, max_width=160, font=0):
    """Wraps a string to the specified width, using the specified
    font, and returns a list of lines.  As a side effect, collapses
    multiple spaces to one."""
    o = ''
    tw = 0
    wspace = width(' ', font)
    for word in string.split(string.strip(s)):
	w = width(word, font)
	if (tw + w) <= max_width:
	    o = o + word + ' '
	    tw = tw + w + wspace
	else:
	    o = o + '\n' + word + ' '
	    tw = w + wspace

    return filter(None, map(string.rstrip, string.split(o, '\n')))
