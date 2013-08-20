#
#  $Id: dtkmain.py,v 1.13 2002/07/15 21:40:28 rob Exp $
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

__version__ = '$Id: dtkmain.py,v 1.13 2002/07/15 21:40:28 rob Exp $'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import sys, os, string
from pprint import pprint

VERSION = '2.1.0'
DATE = "2001/12/26"
IDENT = "Pyrite Publisher v%s (%s) by Rob Tillotson <rob@pyrite.org>" % (VERSION, DATE)

import plugin, dtkplugins, config
from plugin import LOG_DEBUG, LOG_WARNING, LOG_NORMAL, LOG_ERROR

_option = plugin.CLIOptionDescriptor
main_options = [
    _option('help', 'h', 'help', 'Get help', boolean=1),
    _option('list_plugins', 'l', 'list-plugins', 'List available plugins', boolean=1),
    _option('force_plugins', 'P', None, 'Force a specific filter plugin', vtype='NAME', multiple=1),
    _option('list_properties', None, 'list-properties', 'List plugin properties', boolean=1),
    _option('list_tasks', None, 'list-tasks', 'List tasks', boolean=1),
    _option('task', 'T', 'task', 'Select a task', vtype='NAME'),
    ]


class ConversionError(Exception): pass

class Placeholder: pass


# The way plugin autoselection works is more or less as follows:
#
#   - input plugins are chosen based on their ability to handle the
#     filename presented to them (normally this should be done
#     automatically)
#
#     the input plugin, after being given the filename, will return
#     the name of a mimetype for the file.  (This is, in effect, an
#     interface name, for purposes of the chaining described below.)
#
#   - parsers and assemblers are chained according to pairs of
#     interfaces.  They can report to the main program which pairs
#     of (input, output) they can handle, and a priority level
#     which can be used to select an interface when there are more
#     than one choice.
#
#   - output plugins can report which input interfaces they can
#     handle.
#
# To autoselect, first an input plugin is selected, and the mimetype
# of the file determined.  Then, the program will determine all
# possible chains of parser/assembler/output plugins from that mimetype.
# If there is more than one it will pick the "best" one.
#

# Since this architecture supports a variable chain of plugins (except
# for the input, and the fact that it must end with an output) the
# method of "stacking" them will now be more uniform...
#
# Plugins will communicate via "events" which are just method calls on
# an object.  Calls will propagate from input to output; the "driver"
# will be wedged between the input and the first plugin, feeding data
# into the first plugin and letting everything cascade from there.
#
# The way this will work is that at the beginning of processing, each
# plugin will have its "open" method called with the chain as argument,
# and this should return an API object which will be handed to the
# *previous* plugin in the chain once all plugins are open.

# Path finding algorithm from http://www.python.org/doc/essays/graphs.html
def find_all_paths(graph, start, end, path=[]):
    path = path + [start]
    if start == end:
        return [path]
    if not graph.has_key(start):
        return []
    paths = []
    for node in graph[start]:
        if node not in path:
            newpaths = find_all_paths(graph, node, end, path)
            for newpath in newpaths:
                paths.append(newpath)
    return paths

class Chain:
    def __init__(self, plugins):
	self.plugins = plugins

	self.collect_path_info()

	self.path = []

    def debug(self):
	pprint(self.__f_links)
	print

    def pathfind(self, start, end):
        _inputs = {}
        _outputs = {}
        for plugin in self.plugins:
            for pri, inp, outp in plugin.get_supported_links():
                if not _inputs.has_key(inp): _inputs[inp] = []
                if plugin not in _inputs[inp]: _inputs[inp].append((plugin,pri))
                if not _outputs.has_key(outp): _outputs[outp] = []
                if plugin not in _outputs[outp]: _outputs[outp].append(plugin)

        # now find pairs
        _pairs = {}
        for outp in _outputs.keys():
            for outplug in _outputs[outp]:
                for inplug,pri in _inputs.get(outp,[]):
                    if inplug != outplug:
                        _pairs[(outplug,inplug)] = (pri, outp)

        # add terminating nodes
        for outplug in _outputs[None]:
            _pairs[(outplug,None)] = (0,None)
        for inp in _inputs.keys():
            for inplug,pri in _inputs[inp]:
                _pairs[(inp,inplug)] = (pri, inp)

        # now we have the edges of a directed graph in which the vertices are
        # plugins... now we need to find all paths between the start and end

        _graph = {}
        for inp, outp in _pairs.keys():
            if not _graph.has_key(inp): _graph[inp] = []
            if outp not in _graph[inp]: _graph[inp].append(outp)

        paths = find_all_paths(_graph, start, end)
        
        # now figure out priorities and sort them
        ret = []
        for path in paths:
            _p = path[:]
            pri = -len(path)  # prioritize by length too
            for x in range(len(path)-1):
                p,t = _pairs[(_p[x],_p[x+1])]
                pri += p
                if t is not None: path[x+1] = (path[x+1],t)
            ret.append((pri, filter(lambda x: x is not None and type(x) != type(''),
                                    path)))
        ret.sort()
        return ret		    
	
    def collect_path_info(self):
	"""Collects information about possible chains from plugins.
	Every plugin must have a 'get_supported_links' function which
	returns a list of valid chainlinks for this plugin, in the form:
	  [ ( input, output, priority), ... ]
	Note that input plugins are special, because they can return different
	mimetypes, but all other plugins use this interface.  Also note that
	the link specifications must be tuples, because they will be used
	as dictionary keys.

	If the output parameter is None this is an output plugin.
	"""
	links = {}
	r_links = {}
	for plugin in self.plugins:
	    lks = plugin.get_supported_links()
	    for pri, inp, outp in lks:
		if not links.has_key(inp): links[inp] = {}
		if not links[inp].has_key(outp): links[inp][outp] = []
		links[inp][outp].append((pri, plugin))

		if not r_links.has_key(outp): r_links[outp] = {}
		if not r_links[outp].has_key(inp): r_links[outp][inp] = []
		r_links[outp][inp].append((pri, plugin))

	    
	self.__f_links = links
	self.__r_links = r_links


    def open(self, path, *a, **kw):
	self.path = path[:]
	path = path[:]
	path.reverse()

	last = None
	for plugin, protocol in path:
	    last = apply(plugin.open, (self, last, protocol)+a, kw)

	return last

    def close(self):
	for plugin, protocol in self.path:
	    if hasattr(plugin, 'close') and callable(plugin.close):
		plugin.close()
	self.path = []
	    

    def check_plugin(self, namelist, plugin, meth="handles_interface"):
	"""Tests whether a plugin supports one of the named interfaces.
	"""
	l = filter(lambda x, p=plugin, m=meth: getattr(p,m) is not None,
		   map(lambda x: x[1], namelist))
	if not l:
	    raise ConversionError, ("plugin '%s' does not support any of " + \
				    string.join(map(lambda x: x[1], namelist), ',')) \
				    % repr(plugin)
	else:
	    return l[0]
	

    def choose_best_plugin(self, namelist, plugins, meth="handles_interface"):
	"""Choose the best plugin to handle one of several named interfaces.
	"""
	nl = namelist[:]
	nl.sort()
	nl.reverse()
	for mpri, mtype in namelist:
	    l = map(lambda x, t=mtype, m=meth: (getattr(x,m)(t), x), plugins)
	    l.sort()
	    if l:
		return (l[-1][1], mtype)

	raise ConversionError, ("can't find a match for " +
				string.join(map(lambda x: x[1], namelist), ','))
    

# A "task" is like a user interface "macro".  It contains a list
# of plugins to force and properties to set; the idea is that
# the user can select a task and have a bunch of other options
# set appropriately.  Tasks are registered by plugins; the validate()
# method is used to check whether the task is possible to do
# (so a plugin can register tasks which rely on optional plugins).
# Note that the plugin that registers the task isn't forced by
# default... of course it can put its own name in the force list.

class TaskDefinition:
    def __init__(self, api, title, plugins=[], properties={}):
        self.api = api
        self.title = title
        self.plugins = plugins
        self.properties = properties

    def validate(self):
        # return false if this task can't be done
        # (probably because all the needed plugins aren't there)
        return 1
    
class PPInstance:
    def __init__(self):
        if '--DEBUG' in sys.argv:
            self.loglevel = 3
            sys.argv.remove('--DEBUG')
        else:
            self.loglevel = 1
            
        self.wildcards = {}
        self.tasks = {}
        
        self.plugins = dtkplugins.load_all_plugins(self)

        self.input_filters = {}

        self.conf = config.PPConfigProcessor(self.plugins,self)
        self.conf.load(os.path.expanduser('~/.pyrpubrc'))

        self.chain = Chain(self.plugins.values())

        self.preferred_installer = ''

        
    # API.
    def log(self, level, name, string):
        if level <= self.loglevel:
            sys.stdout.write("%s: %s\n" % (name, string))

    def has_plugin(self, n):
        return self.plugins.has_key(n)

    def get_plugin(self, n):
        return self.plugins[k]

    def find_installer(self):
        # figure out what installer the user wants to use, or return none.
        inst_plugins = filter(lambda x: hasattr(x, 'installable_check'), self.plugins.values())
        # first see if the user specified a preference
        if self.preferred_installer: pref = string.lower(self.preferred_installer)
        else: pref = string.lower(self.conf.get('installer', ''))
        if pref:
            for p in inst_plugins:
                if string.lower(p.installer_name) == pref or \
                   string.lower(p.name) == pref:
                    if not p.installable_check():
                        self.log(plugin.LOG_ERROR, 'main', 'cannot install using preferred method "%s"' % pref)
                    else:
                        return p
                    break

        # if we still haven't picked one, sort by priority and choose the best one
        inst_plugins = filter(lambda x: x.installable_check(), inst_plugins)
        if not inst_plugins:
            return None
        inst_plugins.sort(lambda x,y: cmp(x.installer_priority, y.installer_priority))
        #print "chose installer", inst_plugins[-1].name
        return inst_plugins[-1]
    
    def register_task(self, key, *a, **kw):
        t = TaskDefinition(self, *a, **kw)
        if t.validate():
            self.tasks[key] = t
            
    def register_wildcard(self, wildcard, description):
        # GUI support function; registers wildcards for file selector
        self.wildcards[wildcard] = description

    def find_plugins_with_link(self, inp, outp=None):
        return [ p for p in self.plugins.values() if p.has_link(inp, outp) ]

    def set_property_all(self, prop, value):
        for p in self.plugins.values():
            if p.has_property(prop):
                setattr(p, prop, value)
            
    # /API
    
    def find_input_plugin(self, fn):
        """Find an appropriate input plugin.

        Finds the plugin which will handle the given filename, and returns
        it, or None if no plugin can handle the given file.
        """
        l = filter(lambda x: x is not None and x[0] is not None,
                   map(lambda x, n=fn:
                       hasattr(x,"handles_filename")
                       and (x.handles_filename(n),x) or None,
                       self.plugins.values()))
        l.sort()
        if l: return l[-1][1]
        else: return None

    def find_paths(self, mimetypes, forced_plugins=[]):
        """Find conversion paths.

        Finds possible conversion paths beginning with one of the
        specified mimetypes, which include all the forced plugins.
        Returns the pathset from the first matching mimetype.
        """
        # XXX need to come up with some way to handle multiple mimetypes
        # XXX in case a gui wants to prompt a user to choose a path
        paths = None
        for mimetype in mimetypes:
            paths = self.chain.pathfind(mimetype, None)
            # filter out paths which don't contain forced plugins
            for pi in forced_plugins:
                paths = [ p for p in paths
                          if pi in [x for x,y in p[1]] ]

            if paths: break

        paths.sort()
        return (mimetype, paths)

    def find_best_path(self, mimetypes, forced_plugins=[]):
        mimetype, paths = self.find_paths(mimetypes, forced_plugins)
        if paths: return (mimetype, list(paths[-1][1]))
        else: return (None, None)
        
    def convert_file(self, fn, forced_plugins=[]):
        # first, pick an input plugin

        iplug = self.find_input_plugin(fn)
        if iplug is None:
            raise ConversionError, "no plugin knows how to handle '%s'" % fn

        mimetypes, basename = iplug.open_input(fn)

        # the input plugin can return a list of mimetypes, which will be
        # tried in order to find a path.

        mimetype, path = self.find_best_path(mimetypes, forced_plugins)
        
        if path is None:
            mt = mimetypes[:]
            if len(mt) > 1: mt.insert(len(mt)-1, 'or')
            raise ConversionError, "couldn't find a way to convert from %s" % string.join(mt)

        # DEBUG
        print "("+string.join(map(lambda x: x.name, (iplug,)+tuple([x[0] for x in path])),',')+")",
        sys.stdout.flush()
        # /DEBUG

        head = self.chain.open(path, basename)
        input = iplug.open(self.chain, head, "INPUT")

        input.go(mimetype)

        self.chain.close()
        input.close_input()



class PPCLI(PPInstance):
    def __call__(self, argv):
        progname = argv[0]
        argv = argv[1:]
        #print argv

        options = Placeholder()
        oparser = plugin.CLIOptionParser(main_options, options, self.plugins.values())

        options.help = 0
        options.list_plugins = 0
        options.list_properties = 0
        options.list_tasks = 0
        options.force_plugins = []
        # pick a task using argv[0]
        if self.tasks.has_key(os.path.basename(progname)):
            options.task = os.path.basename(progname)
        else:
            options.task = ''
        argv = oparser(argv) # no longer need partial=1

        forced_plugins = []
        # -T option
        if options.task:
            if not self.tasks.has_key(options.task):
                print 'error: no task called "%s".  (use the --list-tasks option to see them)'
                return
            task = self.tasks[options.task]
            print "Selected task: %s" % task.title
            forced_plugins = [self.plugins.get(name,None) for name in task.plugins[:]]
            if None in forced_plugins:
                print 'error: all plugins needed for the selected task are not available'
                return
            for k, v in task.properties.items():
                self.set_property_all(k, v)
                # it would be nice if this didn't override command line options
                # and config file variables, but that seems like it will be
                # a lot of work.
            
        # -P option
        if options.force_plugins:
            for arg in options.force_plugins:
                for pname in map(string.strip, string.split(arg,',')):
                    if not self.plugins.has_key(pname):
                        print self.plugins.keys()
                        print "error: no such plugin '%s'" % pname
                    else:
                        forced_plugins.append(self.plugins[pname])

        if options.list_plugins:
            self.cmd_list_plugins()
            return

        if options.help:
            self.cmd_help(oparser)
            return

        if options.list_properties:
            self.cmd_list_properties()
            return

        if options.list_tasks:
            self.cmd_list_tasks()
            return

        for fn in argv:
            print "Converting %s..." % fn,
            sys.stdout.flush()

            try:
                self.convert_file(fn, forced_plugins)
            except ConversionError, err:
                print "error: %s" % err
                continue
            except IOError, err:
                print "i/o error: %s" % err
                continue

    def cmd_list_tasks(self):
        print IDENT
        print
        if not self.tasks:
            print "No tasks are defined."
            return

        print "Task            Description"
        print "----            -----------"
        keys = self.tasks.keys()
        keys.sort()
        for key, task in [ (key, self.tasks[key]) for key in keys ]:
            print "%-15s %s" % (key, task.title[:62])
            
    def cmd_list_plugins(self):
        ky = self.plugins.keys()
	ky.sort()

        fplugins = [ self.plugins[k] for k in ky if self.plugins[k].get_supported_links() ]
        oplugins = [ self.plugins[k] for k in ky if not self.plugins[k].get_supported_links() ]
        
        print IDENT
        print
        if not fplugins and not oplugins:
            print "No plugins installed?"
            
        if fplugins:
            print "Filter plugins:"
            print
            print "Plugin           Description"
            print "------           -----------"
            for p in fplugins:
                print "%-15s  %-59s" % (p.name, string.split(p.description, '\n')[0][:60])
            print
            
        if oplugins:
            print "Other plugins:"
            print
            print "Plugin           Description"
            print "------           -----------"
            for p in oplugins:
                print "%-15s  %-59s" % (p.name, string.split(p.description, '\n')[0][:60])
            print
        return

    def cmd_help(self, oparser):
        print IDENT
	print
	print oparser.help(main_options)
	print

	ky = self.plugins.keys()
	ky.sort()
	for k in ky:
	    ip = self.plugins[k]
	    if ip.getCLIOptionDescriptors():
		print "Plugin: %s %s by %s <%s>" % (ip.name, ip.version, ip.author,
						    ip.author_email)
		if ip.description: print string.split(ip.description,'\n')[0]

		print
		print oparser.help(ip.getCLIOptionDescriptors())
		print
        return

    def cmd_list_properties(self):
        print IDENT
        print
        print "! = boolean property, # = multiple values allowed"
        print
        ky = self.plugins.keys()
        ky.sort()
        for k in ky:
            ip = self.plugins[k]
            props = filter(lambda x: not x.read_only, ip.getPropertyDescriptors())
            if props:
                props.sort()
                print "Plugin: %s %s by %s <%s>" % (ip.name, ip.version, ip.author,
                                                    ip.author_email)
                print
                for prop in props:
                    if prop.indexed: ty = '#'
                    elif prop.boolean: ty = '!'
                    else: ty = ' '
                    d = string.split(prop.description,'\n')[0][:54]
                    print "  %-20s %s %s" % (prop.name, ty, d)
                print
        return


