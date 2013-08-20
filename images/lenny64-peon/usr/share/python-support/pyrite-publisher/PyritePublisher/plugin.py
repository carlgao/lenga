#
#  $Id: plugin.py,v 1.8 2002/02/05 12:06:14 rob Exp $
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
"""microSulfur plugin support

This is a fairly lightweight plugin interface: it doesn't even
require plugins to import anything.

This module's spiritual ancestor, Sulfur, used an on-demand loader
which would search for a requested plugin at runtime, by attempting to
import it from the packages named along a search path.  While that
method was flexible, it was also somewhat complicated.  Also,
enumeration of plugins was problematic because it was dependent on the
external implementation of the Python package system.

Therefore, this plugin manager uses a more traditional 'load all the
plugins when the program starts' paradigm; lazy-loading can be done
by a class wrapper, if it is desired.  The loaders here use only the
standard Python import mechanism, which should make it easier to
freeze a program that uses this code.

The loaders and other functionality provided by this module assumes
that the calling program will provide a 'callback object' which has
callback methods.  Currently, this object has to provide the following
methods:

   log(level, name, string) - put something in the logfile
"""

__version__ = '$Id: plugin.py,v 1.8 2002/02/05 12:06:14 rob Exp $'

__copyright__ = 'Copyright 2001 Rob Tillotson <rob@pyrite.org>'

import sys, string, os, traceback

def _import(name):
    mod = __import__(name)
    components = string.split(name, '.')
    for comp in components[1:]:
	mod = getattr(mod, comp)
    return mod

class OptionParsingError(Exception): pass
class Callback:
    def __init__(self, loglevel=2, f=sys.stderr):
	self.f = f
	self.level = loglevel
    def log(self, level, name, string):
	if level <= self.level:
	    self.f.write('%s: %s\n' % (name, string))

class SilentCallback:
    def log(self, level, name, string): pass
    
LOG_ERROR = 0
LOG_WARNING = 1
LOG_NORMAL = 2
LOG_DEBUG = 3

class PluginLoader:
    pass

class ObjectLoader(PluginLoader):
    """Plugin loader for class-based plugins.

    This loader assumes that:
      - each plugin is contained in a module, one plugin per module
      - each plugin is instantiated merely by importing it; for example
        a class, which the application will make objects of at runtime
      - the plugin class is located by its name
    """
    def __init__(self, callback=None):
	if callback is None: self.callback = SilentCallback()
	else: self.callback = callback

    def load_plugins(self, modules, obj_name='Plugin'):
	l = []
	for name in modules:
	    self.callback.log(LOG_NORMAL, "plugin loader", "importing %s" % name)
	    try:
		mod = _import(name)
	    except:
                z0,z1,z2 = sys.exc_info()
		self.callback.log(LOG_WARNING, "plugin loader",
				  "warning: import error for %s" % name)
                self.callback.log(LOG_DEBUG, name,
                                  "*** If this is one of the built-in plugins, the following information")
                self.callback.log(LOG_DEBUG, name,
                                  "*** may be helpful to the author in debugging it.")
                for line in string.split(string.join(traceback.format_exception(z0,z1,z2),'\n'),'\n'):
                    self.callback.log(LOG_DEBUG, name, string.rstrip(line))
                continue
            
	    if hasattr(mod, obj_name):
		l.append(getattr(mod, obj_name))
	    else:
		self.callback.log(LOG_WARNING, "plugin loader",
				  "warning: %s has no attribute named '%s'" % (name, obj_name))
	return l

class CallableLoader(ObjectLoader):
    """Plugin loader for callable-based plugins.

    A plugin loader that assumes that:
      - each plugin class is found in a module; one module, one plugin
      - the plugin is obtained by calling a function (or other callable
        thing, eg. a class) in that module
      - the plugin instantiation function is located by its name

    Additional keyword arguments may be provided to the load_plugins
    function to pass them to the classes' __init__ functions.
    """
    def load_plugins(self, modules, func_name='Plugin', **kw):
	l = []
	for cl in ObjectLoader.load_plugins(self, modules, func_name):
	    try:
		i = apply(cl, (), kw)
		l.append(i)
	    except:
                z0,z1,z2 = sys.exc_info()
		self.callback.log(LOG_WARNING, "plugin loader",
				  "warning: error calling %s" % cl)
                self.callback.log(LOG_DEBUG, str(cl),
                                  "*** If this is one of the built-in plugins, the following information")
                self.callback.log(LOG_DEBUG, str(cl),
                                  "*** may be helpful to the author in debugging it.")
                for line in string.split(string.join(traceback.format_exception(z0,z1,z2),'\n'),'\n'):
                    self.callback.log(LOG_DEBUG, str(cl), string.rstrip(line))
	return l

    
class MultipleCallableLoader(ObjectLoader):
    """Plugin loader for modules that may instantiate multiple plugins.

    Like CallableLoader, except the function called will return a list
    or tuple of plugins.
    """
    def load_plugins(self, modules, func_name='load_plugins', **kw):
	l = []
	for cl in ObjectLoader.load_plugins(self, modules, func_name):
	    try:
		i = apply(cl, (), kw)
		l = l + list(i)
	    except:
		self.callback.log(LOG_WARNING, "plugin loader",
				  "error calling %s.%s" % (name, func_name))
	return l

class LazyClass:
    """Lazy loader stub for classes.

    This object fakes a small part of the interface of another object
    (particularly a class object), loading the module containing that
    object when it is needed.

    The arguments to __init__ are the name of the module to import,
    the name of the object within that module that this stub is
    proxying for, and any number of keyword arguments.  The keyword
    arguments are treated as read-only attributes; getattr'ing them
    from the proxy will not cause the real object to be loaded.

    The real object is loaded as soon as the proxy is called.  Once
    that happens, the dummy attributes will be cleared out, and
    getattr requests and calls will be redirected to the real object.
    """
    def __init__(self, module, objname, **kw):
	self.__module = module
	self.__objname = objname
	self.__object = None
	self.__attr = {}
	for k, v in kw:
	    self.__attr[k] = v

    def __load(self):
	mod = _import(self.__module)
	self.__object = getattr(mod, self.__objname)
	self.__attr = {}
	
    def __getattr__(self, k):
	if self.__attr.has_key(k): return self.__attr[k]
	if self.__object is not None:
	    return getattr(self.__object, k)
	else:
	    raise AttributeError, k

    def __setattr__(self, k, v):
	if self.__object is not None:
	    return setattr(self.__object, k, v)
	else:
	    raise AttributeError, k
    
    def __call__(self, *a, **kw):
	if self.__object is None: self.__load()
	return apply(self.__object, a, kw)
    


#
#  And here follow some interface mixins that are useful to plugins.
#  First, the "properties" interface:
#
#  A property is an attribute of a plugin object.  It is just like
#  any other attribute; what makes it a property is that there is
#  an externally visible interface which tells clients of the plugin
#  that it exists.  This is meant to be used for attributes which
#  hold configuration information -- the sort of things that might
#  find a place in a configuration file, on the command line, or
#  in an option dialog.
#
#  The interface to properties is fairly simple: the plugin must have
#  a method called "getPropertyDescriptors" which returns a list of
#  PropertyDescriptor objects.

class PropertyDescriptor:
    def __init__(self, name, description='', indexed=0, boolean=0, read_only=0):
	self.name = name
	self.description = description
	self.indexed = indexed
	self.read_only = read_only
        self.boolean = boolean

    def __cmp__(self, other):
	return cmp(self.name, other.name)

class PropertyMixin:
    """Mixin class for plugins with properties.
    As a convenience this class provides a getPropertyDescriptors function
    which returns a list provided at object initialization time.  If the
    plugin does not want to use that, it must overload getPropertyDescriptors.
    """
    def __init__(self, base='', descriptors=None):
	self.property_base = base
	if descriptors:
	    self.property_descriptors = descriptors

    def getPropertyDescriptors(self):
	return self.property_descriptors

    def getPropertyInfo(self, n):
        for pd in self.getPropertyDescriptors():
            if pd.name == n:
                return pd
            
    def has_property(self, p):
        for pd in self.getPropertyDescriptors():
            if pd.name == p:
                return 1

    def _add_property(self, *a, **kw):
	if not hasattr(self,'property_descriptors'):
	    self.property_descriptors = []
	self.property_descriptors.append(apply(PropertyDescriptor, a, kw))

    def copyProperties(self, target):
        for pd in self.getPropertyDescriptors():
            if hasattr(self, pd.name):
                setattr(target, pd.name, getattr(self, pd.name))
                
	
	
#
#  Command-line support is similar, yet slightly different from the
#  properties interface.  Rather than include support for command line
#  options in the property interface, it is separated out into another
#  mixin.
#
#  As with properties, the main thing the plugin has to do is provide
#  a function, getCLIOptionDescriptors, which returns a list of
#  CLIOptionDescriptor objects.

class CLIOptionDescriptor:
    """Describes a CLI option.

    name - the name of the attribute which will contain the value
    short - the short name (without '-') of this option
    long - the long name (without '--') of this option
      (either short or long, or both, must be supplied)
    help - the help string for this option
    vtype - the 'value type' used in help for this option, for
      example '-a FOO   set bar to FOO bazs', vtype is FOO
    boolean - if true, this option takes no value and is just a toggle
    multiple - if true, this option takes multiple values, and will
      return a list
    func - a function, which must take a string as its only argument,
      which will convert the command-line argument into the form
      needed by the plugin.  It may raise an exception if the value
      is out of range or otherwise invalid.
    """
    def __init__(self, name, short='', long='', help='', vtype='',
		 boolean=0, multiple=0, func=None):
	self.name = name
	self.short = short
	self.long = long
	self.help = help
	self.vtype = vtype
	self.boolean = boolean
	self.multiple = multiple
	self.func = func

    def __cmp__(self, other):
	return cmp(self.name, other.name)
    

class CLIOptionMixin:
    def __init__(self, descriptors=None):
	if descriptors is not None:
	    self.cli_option_descriptors = descriptors

    def getCLIOptionDescriptors(self):
	return self.cli_option_descriptors

    def _add_cli_option(self, *a, **kw):
	if not hasattr(self,'cli_option_descriptors'):
	    self.cli_option_descriptors = []
	self.cli_option_descriptors.append(apply(CLIOptionDescriptor, a, kw))


class CLIOptionParser:
    def __init__(self, opts=None, target=None, plugins=None):
	if opts: self.__opts = opts
	else: self.__opts = []

	self.__target = target

	if plugins: self.__plugins = plugins
	else: self.__plugins = []

    def __call__(self, argv, partial=0):
	# if partial is true, then we don't flag unknown options,
	# we just put them back into argv for a later re-parse

	oshort = {}
	olong = {}

	for o in self.__opts:
	    if o.short:
                if not oshort.has_key(o.short): oshort[o.short] = []
                oshort[o.short].append((o, self.__target))
	    if o.long:
                if not olong.has_key(o.long): olong[o.long] = []
		olong[o.long].append((o, self.__target))

	for p in self.__plugins:
	    for o in p.getCLIOptionDescriptors():
                if o.short:
                    if not oshort.has_key(o.short): oshort[o.short] = []
                    oshort[o.short].append((o, p))
                if o.long:
                    if not olong.has_key(o.long): olong[o.long] = []
                    olong[o.long].append((o, p))

	argv_left = []
	passall = 0
	while argv:
	    a, argv = argv[0], argv[1:]

	    if not a: continue
	    if passall or a[0] != '-':
		argv_left.append(a)
		continue

	    a = a[1:]
	    if not a:
		raise OptionParsingError, 'what the heck does "-" by itself mean?'

	    if a[0] == '-': # long option
		a = a[1:]
		if not a: # we have a --
		    passall = 1
		    continue

		if not olong.has_key(a):
		    if not partial:
			raise OptionParsingError, 'no such option --%s' % a
		    else:
			argv_left.append('--%s' % a)
			continue

                if not argv:
                    arg = None
                    rest = argv
                else:
                    arg = argv[0]
                    rest = argv[1:]
                    
                for opt, target in olong[a]:
                    if opt.boolean:
                        if not hasattr(target, opt.name) or not getattr(target, opt.name):
                            setattr(target, opt.name, 1)
                        else:
                            setattr(target, opt.name, 0)
                    else:
                        if arg is None:
                            raise OptionParsingError, 'option --%s requires a value' % a
                        if opt.func is not None: arg = opt.func(arg)
                        if opt.multiple:
                            if not hasattr(target, opt.name): setattr(target, opt.name, [])
                            getattr(target, opt.name).append(arg)
                        else:
                            setattr(target, opt.name, arg)
                        argv = rest
	    else:
		for aa in a:
		    if not oshort.has_key(aa):
			if not partial:
			    raise OptionParsingError, 'no such option -%s' % aa
			else:
			    argv_left.append('-%s' % a)
			    continue

                    if not argv:
                        arg = None
                        rest = argv
                    else:
                        arg = argv[0]
                        rest = argv[1:]

                    for opt, target in oshort[aa]:
                        if opt.boolean:
                            if not hasattr(target, opt.name) or not getattr(target, opt.name):
                                setattr(target, opt.name, 1)
                            else:
                                setattr(target, opt.name, 0)
                        elif len(a) > 1: # cannot do -xyz if x,y,or z need value
                            raise OptionParsingError, 'option -%s must stand alone because it needs a value' % aa
                        else:
                            if opt.func is not None: arg = opt.func(arg)
                            if opt.multiple:
                                if not hasattr(target, opt.name): setattr(target, opt.name, [])
                                getattr(target, opt.name).append(arg)
                            else:
                                setattr(target, opt.name, arg)
                            argv = rest
			    
	return argv_left
    
    def help(self, op=None):
	l = []

	if op is None:
	    opts = self.__options[:]
	else:
	    opts = op[:]
	opts.sort()

	for o in opts:
	    if o.short: c = '-%s' % o.short
	    else: c = ''

	    if o.long:
		if c: c = c + ', --%s' % o.long
		else: c = '--%s' % o.long

	    if o.vtype: c = c + ' %s' % o.vtype
	    if o.multiple: c = c + ' ...'

	    if len(c) > 26:
		l.append('  %s' % c)
		l.append((' '*(29))+string.split(o.help,'\n')[0][:50])
	    else:
		l.append('  %-26s %s' % (c, string.split(o.help,'\n')[0][:50]))
		
	return string.join(l, '\n')
    
		
