
import sys, os, string, re, htmllib, urllib, urlparse, mimetypes
from pprint import pprint

from dtkplugins import InputPlugin
from dtkmain import ConversionError



class NullFormatter:
    def nothing(self, *a, **kw):
        pass
    
    def __getattr__(self, k):
        return self.nothing
    
class HTMLLinkGatherer(htmllib.HTMLParser):
    def __init__(self):
        htmllib.HTMLParser.__init__(self,NullFormatter())

        self.links = []
        self.images = []

    def anchor_bgn(self, href, name, type):
        self.links.append((href, name, type))

    def handle_image(self, src, alt, *a):
        self.images.append((src, alt))

    def __str__(self):
        l = ['Links:'] + map(str, self.links.keys())
        l = l + ['Images:'] + map(str, self.images.keys())
        return string.join(l,'\n')
    
def gather_links(fn):
    p = HTMLLinkGatherer()
    p.feed(open(fn).read())
    return p
    
def type_and_host(url):
    typ, rest = urllib.splittype(url)
    hostport, rest = urllib.splithost(rest)
    if hostport is None:
        host = None
    else:
        upwd, hostport = urllib.splituser(hostport)
        host, port = urllib.splitport(hostport)
    return typ, host

def guess_mimetype(fn, headers=None):
    try:
        mtype = headers['Content-Type']
    except:
        mtype = 'application/octet-stream'

    if mtype in ['application/octet-stream', 'text/plain']:
        gtype, genc = mimetypes.guess_type(fn)
        return gtype
    else:
        return mtype

class WebSpider:
    def __init__(self, base):
        self.base = base

        self.info = {}

        self.valid_url_types = ['http','ftp','gopher'] #whatever urllib handles
        self.maximum_depth = 3
        self.follow_offsite_links = 0
        self.verbose = 1
        
        typ, host = type_and_host(base)
        self.base_host = host

        self.pages = []
        
    def go(self):
        print "Retrieving", self.base
        fn, headers = urllib.urlretrieve(self.base)
        self.info[self.base] = (fn, headers)

        mtype = guess_mimetype(fn, headers)
        self.pages.append((self.base, mtype, fn, headers))
        
        self.process_links(fn, self.base, 2)

    def process_links(self, fn, url, level=0):
        # If we have reached maximum link depth, quit.
        if self.maximum_depth and level > self.maximum_depth:
            return
        
        lks = gather_links(fn)
        for link, lname, ltype in lks.links:
            nurl = urlparse.urljoin(url, link)
            # decide whether we want to follow this link
            typ, host = type_and_host(nurl)
            if typ is not None and typ not in self.valid_url_types:
                if self.verbose: print "Skipping", nurl, "due to ignored type", typ
                continue

            if host != self.base_host and not self.follow_offsite_links:
                if self.verbose: print "Skipping", nurl, "because it is an offsite link to", host
                continue
            
            sys.stdout.flush()
            if not self.info.has_key(nurl):
                if self.verbose: print "Retrieving", nurl, "(level %s)" % level
                try:
                    fn, headers = urllib.urlretrieve(nurl)
                except IOError: # broken link
                    if self.verbose: print "Broken link", nurl
                    continue
                self.info[nurl] = (fn, headers)
                # if it's HTML, recurse
                mtype = guess_mimetype(fn, headers)
                self.pages.append((nurl, mtype, fn, headers))
                if mtype == 'text/html':
                    self.process_links(fn, nurl, level+1)
                else:
                    if self.verbose: print "Not processing", nurl, "because it isn't html"
            else:
                if self.verbose: print "Not retrieving", nurl, "because it is in cache"
        
class Plugin(InputPlugin):
    name = 'WebInput'
    description = 'Retrieves a web page or site.'

    def __init__(self, *a, **kw):
        InputPlugin.__init__(self, *a, **kw)

        self._add_property('spider','Use web spider')
        self._add_cli_option('spider','','spider',
                             'Use web spider', boolean=1)
        self.spider = 0

        self._add_property('maximum_depth', 'Maximum depth to retrieve')
        self._add_cli_option('maximum_depth', '', 'maxdepth',
                             'Maximum depth to retrieve', vtype="NUM", func=int)
        self.maximum_depth = 1

        self._add_property('follow_offsite_links', 'Follow links off site of main page')
        self._add_cli_option('follow_offsite_links', '', 'offsite-links',
                             'Follow links off site of main page', boolean=1)
        self.follow_offsite_links = 0
        
        self._tempdir = ''

        self._spiderobj = None
        self._base_url = None
        
    def handles_filename(self, fn):
        # XXX later, retrieve the file and spider if it is HTML
        # but behave like URLStream if it is not.
        if self.spider and (fn[:5] == 'http:' or
                            fn[-5:].lower() == '.html' or
                            fn[-4].lower() == '.htm'):
            return 1

    def open_input(self, fn):
        self._base_url = fn
        self._spiderobj = WebSpider(fn)
        self.copyProperties(self._spiderobj)
        self._spiderobj.go()

        #pprint(self._spiderobj.info)
        
        return ['MULTIPART:web'], os.path.basename(fn)
    
    def close_input(self):
        urllib.urlcleanup()

    def go(self, mimetype):
        self.next.process_multipart_web(self._spiderobj.pages[:])
