# Minimal support for git commands on an hg repository
#
# Copyright 2005, 2006 Chris Mason <mason@suse.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# The hgk extension allows browsing the history of a repository in a
# graphical way. It requires Tcl/Tk version 8.4 or later. (Tcl/Tk is
# not distributed with Mercurial.)
#
# hgk consists of two parts: a Tcl script that does the displaying and
# querying of information, and an extension to mercurial named hgk.py,
# which provides hooks for hgk to get information. hgk can be found in
# the contrib directory, and hgk.py can be found in the hgext
# directory.
#
# To load the hgext.py extension, add it to your .hgrc file (you have
# to use your global $HOME/.hgrc file, not one in a repository). You
# can specify an absolute path:
#
#   [extensions]
#   hgk=/usr/local/lib/hgk.py
#
# Mercurial can also scan the default python library path for a file
# named 'hgk.py' if you set hgk empty:
#
#   [extensions]
#   hgk=
#
# The hg view command will launch the hgk Tcl script. For this command
# to work, hgk must be in your search path. Alternately, you can
# specify the path to hgk in your .hgrc file:
#
#   [hgk]
#   path=/location/of/hgk
#
# hgk can make use of the extdiff extension to visualize
# revisions. Assuming you had already configured extdiff vdiff
# command, just add:
#
#   [hgk]
#   vdiff=vdiff
#
# Revisions context menu will now display additional entries to fire
# vdiff on hovered and selected revisions.

import os
from mercurial import commands, util, patch, revlog
from mercurial.node import nullid, nullrev, short

def difftree(ui, repo, node1=None, node2=None, *files, **opts):
    """diff trees from two commits"""
    def __difftree(repo, node1, node2, files=[]):
        assert node2 is not None
        mmap = repo.changectx(node1).manifest()
        mmap2 = repo.changectx(node2).manifest()
        status = repo.status(node1, node2, files=files)[:5]
        modified, added, removed, deleted, unknown = status

        empty = short(nullid)

        for f in modified:
            # TODO get file permissions
            ui.write(":100664 100664 %s %s M\t%s\t%s\n" %
                     (short(mmap[f]), short(mmap2[f]), f, f))
        for f in added:
            ui.write(":000000 100664 %s %s N\t%s\t%s\n" %
                     (empty, short(mmap2[f]), f, f))
        for f in removed:
            ui.write(":100664 000000 %s %s D\t%s\t%s\n" %
                     (short(mmap[f]), empty, f, f))
    ##

    while True:
        if opts['stdin']:
            try:
                line = raw_input().split(' ')
                node1 = line[0]
                if len(line) > 1:
                    node2 = line[1]
                else:
                    node2 = None
            except EOFError:
                break
        node1 = repo.lookup(node1)
        if node2:
            node2 = repo.lookup(node2)
        else:
            node2 = node1
            node1 = repo.changelog.parents(node1)[0]
        if opts['patch']:
            if opts['pretty']:
                catcommit(ui, repo, node2, "")
            patch.diff(repo, node1, node2,
                       files=files,
                       opts=patch.diffopts(ui, {'git': True}))
        else:
            __difftree(repo, node1, node2, files=files)
        if not opts['stdin']:
            break

def catcommit(ui, repo, n, prefix, ctx=None):
    nlprefix = '\n' + prefix;
    if ctx is None:
        ctx = repo.changectx(n)
    (p1, p2) = ctx.parents()
    ui.write("tree %s\n" % short(ctx.changeset()[0])) # use ctx.node() instead ??
    if p1: ui.write("parent %s\n" % short(p1.node()))
    if p2: ui.write("parent %s\n" % short(p2.node()))
    date = ctx.date()
    description = ctx.description().replace("\0", "")
    lines = description.splitlines()
    if lines and lines[-1].startswith('committer:'):
        committer = lines[-1].split(': ')[1].rstrip()
    else:
        committer = ctx.user()

    ui.write("author %s %s %s\n" % (ctx.user(), int(date[0]), date[1]))
    ui.write("committer %s %s %s\n" % (committer, int(date[0]), date[1]))
    ui.write("revision %d\n" % ctx.rev())
    ui.write("branch %s\n\n" % ctx.branch())

    if prefix != "":
        ui.write("%s%s\n" % (prefix, description.replace('\n', nlprefix).strip()))
    else:
        ui.write(description + "\n")
    if prefix:
        ui.write('\0')

def base(ui, repo, node1, node2):
    """Output common ancestor information"""
    node1 = repo.lookup(node1)
    node2 = repo.lookup(node2)
    n = repo.changelog.ancestor(node1, node2)
    ui.write(short(n) + "\n")

def catfile(ui, repo, type=None, r=None, **opts):
    """cat a specific revision"""
    # in stdin mode, every line except the commit is prefixed with two
    # spaces.  This way the our caller can find the commit without magic
    # strings
    #
    prefix = ""
    if opts['stdin']:
        try:
            (type, r) = raw_input().split(' ');
            prefix = "    "
        except EOFError:
            return

    else:
        if not type or not r:
            ui.warn("cat-file: type or revision not supplied\n")
            commands.help_(ui, 'cat-file')

    while r:
        if type != "commit":
            ui.warn("aborting hg cat-file only understands commits\n")
            return 1;
        n = repo.lookup(r)
        catcommit(ui, repo, n, prefix)
        if opts['stdin']:
            try:
                (type, r) = raw_input().split(' ');
            except EOFError:
                break
        else:
            break

# git rev-tree is a confusing thing.  You can supply a number of
# commit sha1s on the command line, and it walks the commit history
# telling you which commits are reachable from the supplied ones via
# a bitmask based on arg position.
# you can specify a commit to stop at by starting the sha1 with ^
def revtree(ui, args, repo, full="tree", maxnr=0, parents=False):
    def chlogwalk():
        count = repo.changelog.count()
        i = count
        l = [0] * 100
        chunk = 100
        while True:
            if chunk > i:
                chunk = i
                i = 0
            else:
                i -= chunk

            for x in xrange(0, chunk):
                if i + x >= count:
                    l[chunk - x:] = [0] * (chunk - x)
                    break
                if full != None:
                    l[x] = repo.changectx(i + x)
                    l[x].changeset() # force reading
                else:
                    l[x] = 1
            for x in xrange(chunk-1, -1, -1):
                if l[x] != 0:
                    yield (i + x, full != None and l[x] or None)
            if i == 0:
                break

    # calculate and return the reachability bitmask for sha
    def is_reachable(ar, reachable, sha):
        if len(ar) == 0:
            return 1
        mask = 0
        for i in xrange(len(ar)):
            if sha in reachable[i]:
                mask |= 1 << i

        return mask

    reachable = []
    stop_sha1 = []
    want_sha1 = []
    count = 0

    # figure out which commits they are asking for and which ones they
    # want us to stop on
    for i in xrange(len(args)):
        if args[i].startswith('^'):
            s = repo.lookup(args[i][1:])
            stop_sha1.append(s)
            want_sha1.append(s)
        elif args[i] != 'HEAD':
            want_sha1.append(repo.lookup(args[i]))

    # calculate the graph for the supplied commits
    for i in xrange(len(want_sha1)):
        reachable.append({});
        n = want_sha1[i];
        visit = [n];
        reachable[i][n] = 1
        while visit:
            n = visit.pop(0)
            if n in stop_sha1:
                continue
            for p in repo.changelog.parents(n):
                if p not in reachable[i]:
                    reachable[i][p] = 1
                    visit.append(p)
                if p in stop_sha1:
                    continue

    # walk the repository looking for commits that are in our
    # reachability graph
    for i, ctx in chlogwalk():
        n = repo.changelog.node(i)
        mask = is_reachable(want_sha1, reachable, n)
        if mask:
            parentstr = ""
            if parents:
                pp = repo.changelog.parents(n)
                if pp[0] != nullid:
                    parentstr += " " + short(pp[0])
                if pp[1] != nullid:
                    parentstr += " " + short(pp[1])
            if not full:
                ui.write("%s%s\n" % (short(n), parentstr))
            elif full == "commit":
                ui.write("%s%s\n" % (short(n), parentstr))
                catcommit(ui, repo, n, '    ', ctx)
            else:
                (p1, p2) = repo.changelog.parents(n)
                (h, h1, h2) = map(short, (n, p1, p2))
                (i1, i2) = map(repo.changelog.rev, (p1, p2))

                date = ctx.date()[0]
                ui.write("%s %s:%s" % (date, h, mask))
                mask = is_reachable(want_sha1, reachable, p1)
                if i1 != nullrev and mask > 0:
                    ui.write("%s:%s " % (h1, mask)),
                mask = is_reachable(want_sha1, reachable, p2)
                if i2 != nullrev and mask > 0:
                    ui.write("%s:%s " % (h2, mask))
                ui.write("\n")
            if maxnr and count >= maxnr:
                break
            count += 1

def revparse(ui, repo, *revs, **opts):
    """Parse given revisions"""
    def revstr(rev):
        if rev == 'HEAD':
            rev = 'tip'
        return revlog.hex(repo.lookup(rev))

    for r in revs:
        revrange = r.split(':', 1)
        ui.write('%s\n' % revstr(revrange[0]))
        if len(revrange) == 2:
            ui.write('^%s\n' % revstr(revrange[1]))

# git rev-list tries to order things by date, and has the ability to stop
# at a given commit without walking the whole repo.  TODO add the stop
# parameter
def revlist(ui, repo, *revs, **opts):
    """print revisions"""
    if opts['header']:
        full = "commit"
    else:
        full = None
    copy = [x for x in revs]
    revtree(ui, copy, repo, full, opts['max_count'], opts['parents'])

def config(ui, repo, **opts):
    """print extension options"""
    def writeopt(name, value):
        ui.write('k=%s\nv=%s\n' % (name, value))

    writeopt('vdiff', ui.config('hgk', 'vdiff', ''))


def view(ui, repo, *etc, **opts):
    "start interactive history viewer"
    os.chdir(repo.root)
    optstr = ' '.join(['--%s %s' % (k, v) for k, v in opts.iteritems() if v])
    cmd = ui.config("hgk", "path", "/usr/share/mercurial/hgk") + " %s %s" % (optstr, " ".join(etc))
    ui.debug("running %s\n" % cmd)
    util.system(cmd)

cmdtable = {
    "^view":
        (view,
         [('l', 'limit', '', 'limit number of changes displayed')],
         'hg view [-l LIMIT] [REVRANGE]'),
    "debug-diff-tree":
        (difftree,
         [('p', 'patch', None, 'generate patch'),
          ('r', 'recursive', None, 'recursive'),
          ('P', 'pretty', None, 'pretty'),
          ('s', 'stdin', None, 'stdin'),
          ('C', 'copy', None, 'detect copies'),
          ('S', 'search', "", 'search')],
         'hg git-diff-tree [OPTION]... NODE1 NODE2 [FILE]...'),
    "debug-cat-file":
        (catfile,
         [('s', 'stdin', None, 'stdin')],
         'hg debug-cat-file [OPTION]... TYPE FILE'),
    "debug-config":
        (config, [], 'hg debug-config'),
    "debug-merge-base":
        (base, [], 'hg debug-merge-base node node'),
    "debug-rev-parse":
        (revparse,
         [('', 'default', '', 'ignored')],
         'hg debug-rev-parse REV'),
    "debug-rev-list":
        (revlist,
         [('H', 'header', None, 'header'),
          ('t', 'topo-order', None, 'topo-order'),
          ('p', 'parents', None, 'parents'),
          ('n', 'max-count', 0, 'max-count')],
         'hg debug-rev-list [options] revs'),
}
