#
#  $Id: entitydefs.py,v 1.1 2001/03/29 21:15:44 rob Exp $
#
#  Copyright 1998-2001 Rob Tillotson <robt@debian.org>
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

__version__ = '$Id: entitydefs.py,v 1.1 2001/03/29 21:15:44 rob Exp $'

__copyright__ = 'Copyright 1998-2001 Rob Tillotson <rob@pyrite.org>'

import htmlentitydefs

palm_entitydefs = {
    # PalmOS fills the unused portion of the character set with an
    # eclectic mix of characters from various ISO standards.
    # Entity names from HTML 4.
    'OElig':    chr(0x8c), # OE ligature
    'oelig':    chr(0x9c), # oe ligature
    'Scaron':   chr(0x8a), # S with caron
    'scaron':   chr(0x9a), # s with caron
    'Yuml':     chr(0x9f), # Y with umlaut
    'circ':     chr(0x88), # circumflex
    'tilde':    chr(0x98), # small tilde
    'ndash':    chr(0x96), # en dash
    'mdash':    chr(0x97), # em dash
    'lsquo':    chr(0x91), # left single quotation mark
    'rsquo':    chr(0x92), # right single quotation mark
    'ldquo':    chr(0x93), # left double quotation mark
    'rdquo':    chr(0x94), # right double quotation mark
    'dagger':   chr(0x86), # dagger
    'Dagger':   chr(0x87), # double dagger
    'permil':   chr(0x89), # per mille sign (wierd percent sign?)
    'lsaquo':   chr(0x8b), # left single angle quotation mark
    'rsaquo':   chr(0x9b), # right single angle quotation mark
    'fnof':     chr(0x83), # latin small f with hook (function def)
    'bull':     chr(0x95), # bullet
    'hellip':   chr(0x85), # horizontal ellipsis
    'trade':    chr(0x99), # trademark sign
    'spades':   chr(0x90), # spade suit
    'clubs':    chr(0x8e), # club suit
    'hearts':   chr(0x8f), # heart suit
    'diams':    chr(0x8d), # diamond suit
    # Characters I can't find reference to anywhere else.
    'dcomma':   chr(0x84), # double comma
    # PalmOS-specific characters.
    'grafcmd':  chr(0x9d), # graffiti command stroke
    'grafsc':   chr(0x9e), # graffiti shortcut stroke
    # RichReader supports this
    'euro':     chr(0x80),
    }


entitydefs = {}

entitydefs.update(htmlentitydefs.entitydefs)
entitydefs.update(palm_entitydefs)
