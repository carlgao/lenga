#!/usr/bin/env python

# Copyright (C) 2009  Ksplice, Inc.
# Author: Waseem Daher
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
# 02110-1301, USA.


## (Partially) implement the parts of hashlib we need, 
## for our Py2.3 and Py2.4 clients
from sha import sha as sha1
