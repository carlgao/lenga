#!/usr/bin/env python

# Copyright (C) 2008-2011 Ksplice, Inc.
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

import sys
import datetime
import errno
import os
import os.path
import re
import socket
import urllib
import posixpath
import pycurl
import cStringIO as StringIO
import ConfigParser
import select
import logging
import random
import traceback
import textwrap
import glob

if sys.version_info >= (2, 6, 2, 'final', 0):  # subprocess_compat comes from 2.6.2
    import subprocess
else:
    import subprocess_compat as subprocess

try: set
except NameError: from sets import Set as set

import yaml
try:
    from yaml import CSafeLoader as yaml_loader
    from yaml import CSafeDumper as yaml_dumper
except ImportError:
    from yaml import SafeLoader as yaml_loader
    from yaml import SafeDumper as yaml_dumper

from uptrack import version

try:
    import gconf
    have_gconf = True
except ImportError:
    have_gconf = False

__version__ = version.version
STATUS_FILE_FORMAT_VERSION = "2"
USERAGENT='Uptrack/' + __version__
BUG_EMAIL='support@ksplice.com'
USE_SERVER_RESOLVER=True
UPTRACK_CONFIG_FILE='/etc/uptrack/uptrack.conf'
UPTRACK_UUID_FILE='/var/lib/uptrack/uuid'
UPTRACK_SERIAL_FILE='/var/lib/uptrack/serial'
UPTRACK_CACHE_DIR="/var/cache/uptrack"
UPDATE_REPO_URL="https://updates.ksplice.com/update-repository"

# We can't put this under /var/cache/uptrack, because we want
# it to be world-readable.
UPTRACK_EFFECTIVE_KERNEL_FILE='/var/lib/uptrack/effective_kernel'

# This value, in Uptrack.Result.code, indicates that the error was due
# to a network failure.
ERROR_NO_NETWORK = 10
# Uptrack threw an unhandled exception
ERROR_INTERNAL_ERROR = 11
# User answered "no" to the confirmation prompt
ERROR_USER_NO_CONFIRM = 12
# Running kernel is not supported by Uptrack
ERROR_UNSUPPORTED = 13
# The user's access key was invalid
ERROR_INVALID_KEY = 14
# The Uptrack client is too old to manage the updates
ERROR_TOO_OLD_INSTALL = 15
# The Uptrack client is too old to even parse packages.yml
ERROR_TOO_OLD_PARSE = 16
# Your subscription to the Ksplice Uptrack service has expired
ERROR_EXPIRED = 17
# The Uptrack server returned an internal error
ERROR_INTERNAL_SERVER_ERROR = 18
# The machine has not yet been activated for use with the Uptrack service.
ERROR_MACHINE_NOT_ACTIVATED = 19
# The user's access key is missing
ERROR_MISSING_KEY = 20
# The sysfs filesystem isn't mounted at /sys
ERROR_SYS_NOT_MOUNTED = 21

def mkdirp(dir):
    """
    Essentially, mkdir -p
    """
    try:
        os.makedirs(dir)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

def write_file(path, data):
    fh = open(path, 'w')
    try:
        fh.write(data)
    finally:
        fh.close()

# Accept a mode argument so that callers can pass 'rb' if they need binary IO.
def read_file(path, mode='r'):
    fh = open(path, mode)
    try:
        return fh.read()
    finally:
        fh.close()

def yaml_load(stream, **kwargs):
    return yaml.load(stream, Loader=yaml_loader, **kwargs)

def yaml_dump(obj, stream=None, **kwargs):
    return yaml.dump(obj, stream, Dumper=yaml_dumper, **kwargs)

def getConfigBooleanOrDie(config, section, option, default):
    """
    Return the value of a boolean config option, or `default` if no value is
    given.

    Raise a ResultException on invalid (non-boolean) values.
    """
    if config.has_option(section, option):
        try:
            return config.getboolean(section, option)
        except ValueError, e:
            msg = """Unable to read %s setting from %s.
%s
Please check that %s is set to 'yes' or 'no' and try again.""" % (
                option, UPTRACK_CONFIG_FILE, e, option)
            raise ResultException(1, msg)
    else:
        return default

def queryRealArch(userarch):
    try:
        p = subprocess.Popen(['setarch', 'linux64', 'uname', '-m'], stdout = subprocess.PIPE,
                             stderr = subprocess.PIPE)
        out = p.communicate()[0].strip()
        if p.returncode == 0:
            return out

        p = subprocess.Popen(['setarch', 'x86_64', 'uname', '-m'], stdout = subprocess.PIPE,
                             stderr = subprocess.PIPE)
        out = p.communicate()[0].strip()
        if p.returncode == 0:
            return out
    except (subprocess.CalledProcessError, OSError):
        logging.debug("Unable to determine the kernel architecture")
        logging.debug(traceback.format_exc())

    return userarch

def getUname():
    """
    Gets the uname, but lies a little, since the arch field is
    actually governed by 'personality' and not the real architecture.

    Note that this returns both the architecture Uptrack is being run
    under, as well as the architecture of the kernel itself (i.e.
    'uname -m' and 'linux64 uname -m').
    """
    sysname, hostname, release, version, userarch = os.uname()

    arch = queryRealArch(userarch)
    if arch in ['i686', 'i586', 'i486']: arch = 'i386'
    if userarch in ['i686', 'i586', 'i486']: userarch = 'i386'

    uname = (sysname, hostname, release, version, arch, userarch)
    return uname


__curl = None
def initCurl(config=None):
    """Initialize the shared cURL object for getCurl().

    """
    global __curl
    if __curl is None:
        __curl = pycurl.Curl()
        __curl.setopt(pycurl.USERAGENT, USERAGENT)
        __curl.setopt(pycurl.OPT_FILETIME, 1)
        __curl.setopt(pycurl.FOLLOWLOCATION, 1)
        __curl.setopt(pycurl.MAXREDIRS, 5)
        __curl.setopt(pycurl.ENCODING, '')
        if config and config.ssl_ca_certs:
            for type, value in config.ssl_ca_certs:
                __curl.setopt(type, value)
        else:
            __curl.setopt(pycurl.CAINFO, "/usr/share/uptrack/ca-certificates.crt")
        __curl.setopt(pycurl.CONNECTTIMEOUT, 30)
        __curl.setopt(pycurl.TIMEOUT, 600)
        if config and config.proxy is not None:
            __curl.setopt(pycurl.PROXY, config.proxy)
        if config and getattr(config, 'verbose', 0) > 1:
            __curl.setopt(pycurl.VERBOSE, 1)

def getCurl():
    """Return a shared cURL object for use by Uptrack.

    For performance, this always returns the same cURL object, in
    order to allow libcURL to reuse connections as much as
    possible. In order for this to work properly, callers should
    always explicitly set the HTTP method they desire before calling
    `.perform()`, and should reset any other unusual properties they
    set on the cURL object to a reasonable default value when they're
    done.

    Needless to say, this is not thread-safe.

    You must call initCurl() before using this function.
    """
    return __curl


def verrevcmp(a, b):
    """Emulates dpkg's verrevcmp() in lib/vercmp.c."""
    def order(x):
        if x == '~':    return -1
        if x.isdigit(): return 0
        if not x:       return 0
        if x.isalpha(): return ord(x)
        return ord(x) + 256

    def num(s):
        if not s: return 0
        return int(s)

    while a or b:
        first_diff = 0
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            d = cmp(order(a[:1]), order(b[:1]))
            if d: return d
            a = a[1:]; b = b[1:]

        an, a = re.match('^([0-9]*)(.*)', a).groups()
        bn, b = re.match('^([0-9]*)(.*)', b).groups()
        d = cmp(num(an), num(bn))
        if d: return d
    return 0

def parseversion(v):
    """Emulates dpkg's parseversion(), in lib/parsehelp.c."""
    if ':' in v:
        epochstr, rest = v.split(':', 1)
        epoch = int(epochstr)
    else:
        epoch = 0
        rest = v

    if '-' in rest:
        version, revision = rest.split('-', 1)
    else:
        version, revision = rest, ''

    return epoch, version, revision

def compareversions(a, b):
    """Emulates dpkg --compare-versions.  Returns -1, 0, 1 like cmp()."""
    ae, av, ar = parseversion(a)
    be, bv, br = parseversion(b)
    return cmp(ae, be) or verrevcmp(av, bv) or verrevcmp(ar, br)

def cmp_order(a, b):
    return cmp(a.order, b.order)

class Result(object):
    def __init__(self, code = 0, message = ''):
        self.code = code
        self.message = message
        self.succeeded = []
        self.failed = []
        self.debug = None
        self.alert = None
        self.desupported = None
        self.tray_icon_error = None
        self.newkernel = False
        self.uptrack_log = None

def resultFromPycurl(config, e):
    if e[0] in [pycurl.E_COULDNT_RESOLVE_HOST,
                pycurl.E_COULDNT_CONNECT,
                pycurl.E_OPERATION_TIMEOUTED]:
        msg = ("Could not connect to the Ksplice Uptrack server. "
               "A network connection is needed to ensure you have "
               "the latest list of updates to install. "
               "Please check your Internet connection and try again. "
               "If this computer does not have direct access to the Internet, "
               "you will need to configure an https proxy in %s." % UPTRACK_CONFIG_FILE)
    elif e[0] == pycurl.E_COULDNT_RESOLVE_PROXY:
        msg = ("Could not resolve your proxy server (%s) while trying to "
               "connect to the Ksplice Uptrack server.  You should check that "
               "this machine can directly connect to the proxy server configured "
               "in %s." % (config.proxy, UPTRACK_CONFIG_FILE))
    elif e[0] == pycurl.E_URL_MALFORMAT:
        msg = ("Malformed URL <%s> for Uptrack server.  Please correct the "
               "value of Network.update_repo_url in %s." %
               (config.remoteroot, UPTRACK_CONFIG_FILE))
    elif e[0] == pycurl.E_SSL_CACERT:
        msg = "Could not verify the Ksplice Uptrack server's SSL certificate. "
        if config.remoteroot == UPDATE_REPO_URL:
            msg += ("Check your network configuration, and contact %s for "
                    "assistance if you are unable to resolve this error." %
                    (BUG_EMAIL,))
        else:
            msg += ("You may need to update ssl_ca_cert_file or "
                    "ssl_ca_cert_dir in %s with the path to an appropriate "
                    "CA. Please consult %s for assistance if you are "
                    "unable to resolve this error." %
                    (UPTRACK_CONFIG_FILE, BUG_EMAIL))
    else:
        msg = ("Unexpected error communicating with the Ksplice Uptrack server. "
               "Please check your network connection and try again. "
               "If this error re-occurs, e-mail %s. " %
               (BUG_EMAIL,))

    msg = textwrap.fill(msg) + "\n\n(Network error: " + e[1] + ")"

    return Result(ERROR_NO_NETWORK, msg)

class ResultException(Exception):
    def __init__(self, code, message):
        # We can't use super here because Exception is an old-style
        # class in python 2.4
        Exception.__init__(self, code, message)
        self.result = Result(code, message)

server_error_exception = ResultException(ERROR_INTERNAL_SERVER_ERROR, """\
The Ksplice Uptrack service has experienced a transient error. Please
wait a few minutes and try again. If this error persists, please
contact %s for assistance.""" % (BUG_EMAIL,))

class ActionResult(object):
    def __init__(self, update, command):
        self.code = 0
        self.message = ''
        self.update = update
        self.command = command
        self.abort_code = None
        self.stack_check_processes = None
        self.nomatch_modules = None
        self.locked_modules = []
        self.usedby_modules = []
        self.depmod_needed = False
        self.debug = ''
        self.core_version = update.getCoreVersion()

    def asDict(self):
        d = {}
        d['Command'] = self.command
        d['ID'] = self.update.id
        d['Name'] = self.update.name
        d['Message'] = self.message
        d['Abort'] = self.abort_code
        d['Core Version'] = self.core_version
        d['Stack Check'] = self.stack_check_processes
        d['Nonmatching Modules'] = self.nomatch_modules
        d['Locked Modules'] = self.locked_modules
        d['UsedBy Modules'] = self.usedby_modules
        return d

def getKernelDict():
    sysname, _, release, version, userarch = os.uname()
    return { 'Sysname':          sysname
           , 'Release':          release
           , 'Version':          version
           , 'UserArchitecture': userarch }

class Status(object):
    def __init__(self, statusdir):
        self.statusdir = statusdir
        self.statusloc = os.path.join(statusdir, 'status')
        self.resultsloc = os.path.join(statusdir, 'results')
        self.upgradeloc = os.path.join(statusdir, 'upgrade_plan')
        self.stamploc = os.path.join(statusdir, 'results.server-stamp')

    # An explanation of return values:
    # - 'None' means status or results file does not exist
    # - If x is returned, x['Result']['Code'] will be populated
    #   with an error code and if the error code is nonzero,
    #   x['Result']['Message'] will have an error message.
    # - If the error code is 2, then the upgrade plan are not available
    # - If the error code is 3, then the installed updates are not available.
    def readStatus(self):
        try:
            f = open(self.statusloc)
            status = yaml_load(f)
            f.close()
        except IOError, e:
            if e.errno == errno.EACCES:
                if os.path.exists('/etc/debian_version'):
                    recommendation = 'sudo adduser $USER adm'
                else:
                    recommendation = 'gpasswd -a <your username> adm (as root)'
                status = {}
                status['Result'] = {}
                status['Result']['Code'] = 3
                status['Result']['Message'] = \
                    ("Permission denied reading the status file.  You need to be in the adm "
                     "group in order to use the the Ksplice Uptrack Manager; you can add yourself by running\n\n"
                     "%s\n\nYou will need to log out and back in "
                     "for this change to take effect." % recommendation)
                return status
            elif e.errno == errno.ENOENT:
                return None
            else:
                status = {}
                status['Result'] = {}
                status['Result']['Code'] = 3
                status['Result']['Message'] = "Error reading status file (%s): %s\n" % \
                                              (self.statusloc, os.strerror(e.errno))
                return status
        try:
            f = open(self.upgradeloc)
            upgrade = yaml_load(f)
            f.close()
            status.update(upgrade)
        except IOError, e:
            if e.errno == errno.ENOENT:
                status['Plan'] = []
            else:
                status['Plan'] = []
                status['Result'] = {}
                status['Result']['Code'] = 2
                status['Result']['Message'] = "Error reading upgrade plan (%s): %s\n" % \
                                              (self.upgradeloc, os.strerror(e.errno))
                return status
        try:
            f = open(self.resultsloc)
            results = yaml_load(f)
            f.close()
            status.update(results)
        except IOError, e:
            status['Result'] = {}
            if e.errno == errno.ENOENT:
                status['Result']['Code'] = 0
            else:
                status['Result']['Code'] = 1
                status['Result']['Message'] = "Error reading results file (%s): %s\n" % \
                                              (self.resultsloc, os.strerror(e.errno))

        return status

    def _writeFile(self, contents, file):
        dir = os.path.dirname(file)
        if not os.path.isdir(dir):
            os.makedirs(dir)
        f = open(file, 'w')
        yaml_dump(contents, f, version=(1, 1),
                  explicit_start=True, explicit_end=True)
        f.close()

    def addIdentity(config, d, local_status=None):
        d['Client'] = {}
        d['Client']['Hostname'] = getattr(config, 'hostname', None)
        d['Client']['FullHostname'] = getattr(config, 'fullhostname', None)
        d['Client']['Key'] = config.accesskey
        d['Client']['UUID'] = config.uuid
        if config.newuuid:
            d['Client']['NewUUID'] = config.newuuid
        if config.olduuid:
            d['Client']['OldUUID'] = config.olduuid

        d['Client']['CPUInfo'] = config.cpuinfo
        d['Client']['UptrackVersion'] = __version__
        try:
            d['Client']['Uptime'] = read_file('/proc/uptime').split()[0]
        except IOError:
            logging.debug(traceback.format_exc())
            d['Client']['Uptime'] = -1
        try:
            d['Client']['RebootsSaved'] = len(file(os.path.join(config.localroot,
                                                                'reboots_saved')).readlines())
        except IOError, e:
            if e.errno == errno.ENOENT:
                d['Client']['RebootsSaved'] = 0
            else:
                d['Client']['RebootsSaved'] = -1
                logging.debug(traceback.format_exc())
        if inVirtualBox():
            d['Client']['VirtualBox'] = True
        d['Client']['VMInfo'] = config.vminfo
        if 'IP' in config.localip:
            d['Client']['LocalIP'] = config.localip['IP']
        else:
            d['Client']['LocalIP_error'] = config.localip['Error']
        d['Client']['Config'] = {}
        d['Client']['Config']['Autoinstall'] = getattr(config, 'cron_autoinstall', False)
        if getattr(config, 'init', None) is not None:
            d['Client']['Config']['Init'] = getattr(config, 'init')
        d['Client']['Config']['Cron'] = getattr(config, 'cron', False)
        d['Client']['MmapMinAddr'] = getMmapMinAddr()
        serial_stat = getattr(config, 'serial_stat', None)
        if serial_stat is not None:
            d['Client']['SerialStat'] = serial_stat

        d['Client']['Tools'] = {}
        for key, path in [('Depmod', '/sbin/depmod'), ('Modprobe', '/sbin/modprobe')]:
            val = {}
            try:
                val['Stat'] = tuple(os.stat(path))
            except OSError:
                val['Stat'] = ()
            try:
                val['Link'] = os.readlink(path)
            except OSError:
                val['Link'] = ''
            d['Client']['Tools'][key] = val

        d['Kernel'] = {}
        d['Kernel']['Sysname'] = config.sysname
        d['Kernel']['Release'] = config.release
        d['Kernel']['Version'] = config.version
        d['Kernel']['Architecture'] = config.arch
        d['Kernel']['UserArchitecture'] = config.userarch

        if config.run_uuid:
            d['RunUUID'] = config.run_uuid
        else:
            d['RunUUID_error'] = config.run_uuid_error

        if local_status is not None:
            effective = local_status.getEffective()
            if effective is not None:
                effective = effective['PackageVersion']
            d['ClientEffectiveKernel'] = effective
    addIdentity = staticmethod(addIdentity)

    def writeStatus(self, local, new_client, installed_updates):
        status = {}
        status['Status format version'] = STATUS_FILE_FORMAT_VERSION
        status['Time'] = datetime.datetime.utcnow()
        self.addIdentity(local.client_config, status, local_status=local)
        status['Updates'] = {}
        status['Updates']['Installed'] = []
        # Python 2.3 doesn't have sorted() or sort(key = ...)
        installed_sorted = list(installed_updates)
        installed_sorted.sort(cmp_order)
        for u in installed_sorted:
            d = {}
            d['ID'] = u.id
            d['Name'] = u.name
            status['Updates']['Installed'].append(d)
        status['New client'] = new_client
        self._writeFile(status, self.statusloc)

    def writeResults(self, local, res):
        results = {}
        results['Results format version'] = STATUS_FILE_FORMAT_VERSION
        results['Time'] = datetime.datetime.utcnow()
        self.addIdentity(local.client_config, results, local_status=local)
        results['Result'] = {}
        results['Result']['Succeeded'] = []
        for action in res.succeeded:
            d = action.asDict()
            results['Result']['Succeeded'].append(d)
        results['Result']['Failed'] = []
        for action in res.failed:
            d = action.asDict()
            results['Result']['Failed'].append(d)
        results['Result']['Code'] = res.code
        results['Result']['Message'] = res.message
        if res.debug is not None:
            results['Debug'] = res.debug
        if res.uptrack_log is not None:
            results['UptrackLog'] = res.uptrack_log
        if res.alert is not None:
            results['Result']['Alert'] = res.alert
        if res.desupported is not None:
            results['Result']['Desupported'] = res.desupported
        if res.tray_icon_error is not None:
            results['Result']['TrayIconError'] = res.tray_icon_error
        if res.newkernel:
            results['Result']['New Kernel'] = True
        if local.client_config.uninstall:
            results['Result']['Uninstalled'] = True

        self._writeFile(results, self.resultsloc)

    def writePlan(self, name, actions):
        plan = {}
        plan[name.title()+' plan format version'] = STATUS_FILE_FORMAT_VERSION
        plan['Time'] = datetime.datetime.utcnow()
        plan['Plan'] = [ dict([(k, act[k]) for k in
                               ('Command', 'ID', 'Name', 'EffectiveKernel') if k in act])
                         for act in actions ]
        self._writeFile(plan, os.path.join(self.statusdir, name+'_plan'))

    def writeUpgradePlan(self, plan):
        self.writePlan('upgrade', plan)

    def writeInitPlan(self, plan):
        self.writePlan('init', plan)

    def writeRemovePlan(self, plan):
        self.writePlan('remove', plan)

    def writeEffectiveKernel(self, effective, ids):
        out = { 'EffectiveKernel': effective
              , 'OriginalKernel':  getKernelDict()
              , 'Installed':       ids }
        self._writeFile(out, UPTRACK_EFFECTIVE_KERNEL_FILE)

    def sendResultToServer(self, config):
        try:
            ## Results file might not exist if this is the first time
            ## uptrack is run and there is nothing to report (e.g. 'show')
            contents = read_file(self.resultsloc)
        except IOError:
            return

        results_time = yaml_load(contents)['Time']
        try:
            stamp_time = yaml_load(read_file(self.stamploc))
            if stamp_time >= results_time:
                return
        except (IOError, yaml.YAMLError, TypeError):
            pass

        status_url = posixpath.join(config.remote,
                                    urllib.quote('result'))
        c = getCurl()
        c.setopt(pycurl.URL, status_url)
        c.setopt(pycurl.HTTPPOST, [('result', contents)])
        c.setopt(pycurl.WRITEFUNCTION, lambda data: None)
        c.perform()

        yaml_dump(results_time, file(self.stamploc, 'w'))

class LocalStatus(object):
    def __init__(self, config, remote_repo, logger):
        self.client_config = config
        self.statusdir = config.local
        self.installed = set()
        self.new_client = False
        self.effective_kernel = None
        self.remote_repo = remote_repo
        self.logger = logger

    def getInstalledIDs(self):
        installed_ids = []
        for f in glob.glob('/sys/module/ksplice_*/ksplice'):
            if read_file(os.path.join(f,'stage')).strip() == 'applied':
                installed_ids.append(re.match('^/sys/module/ksplice_(.*)/ksplice$',
                                              f).group(1))
        for f in glob.glob('/sys/kernel/ksplice/*/stage'):
            if read_file(f).strip() == 'applied':
                installed_ids.append(re.match('^/sys/kernel/ksplice/(.*)/stage$',
                                              f).group(1))
        return installed_ids

    def setEffective(self, effective):
        sysname, arch, release, version = effective[0].split('/')
        self.effective_kernel = {
            'Sysname'       : sysname
          , 'Architecture'  : arch
          , 'Release'       : release
          , 'Version'       : version
          , 'PackageVersion': effective[1] }

    def getEffective(self):
        """Returns the effective kernel, either as set in this run or as
           loaded from disk.  Returns None if the effective kernel cannot
           be determined."""
        if self.effective_kernel is not None:
            return self.effective_kernel

        try:
            f = open(UPTRACK_EFFECTIVE_KERNEL_FILE, 'r')
            effective = yaml_load(f)
            f.close()
        except (IOError, yaml.YAMLError):
            return None

        # Check that we booted into the same kernel as when the effective kernel
        # data was written.
        if getKernelDict() != effective['OriginalKernel']:
            return None

        # Check that we have the same updates loaded now as then.
        were_installed = set(effective['Installed'])
        now_installed  = set(self.getInstalledIDs())
        if were_installed != now_installed:
            return None

        self.effective_kernel = effective['EffectiveKernel']
        return self.effective_kernel

    def getInstalledUpdates(self):
        list_installed = []
        for id in self.getInstalledIDs():
            u = self.remote_repo.idToUpdate(id)
            if u:
                list_installed.append(u)

        self.installed = set(list_installed)
        return self.installed

    def unpackPlan(self, plan):
        """Augment a plan we read or downloaded with some extra info."""
        for act in plan:
            act['Update'] = self.remote_repo.idToUpdate(act['ID'])
            act['Name']   = act['Update'].name

    def readPlan(self, which_plan):
        f = open(os.path.join(self.statusdir, which_plan + '_plan'), "r")
        actions = yaml_load(f)['Plan']
        f.close()
        self.unpackPlan(actions)
        return actions

    def writeOutStatus(self, res, upgrade_plan, init_plan, remove_plan):
        s = Status(self.statusdir)
        logging.debug("Writing status to file.")
        try:
            # Call getEffective in case the file already has an effective
            # version, which we have neither loaded nor updated.
            self.getEffective()
            installed = self.getInstalledUpdates()
            s.writeStatus(self, self.new_client, installed)
            if res is not None:
                if res.code != 0:
                    res.uptrack_log = self.logger.getDebugLog()
                s.writeResults(self, res)
            if upgrade_plan is not None:
                s.writeUpgradePlan(upgrade_plan)
            if init_plan is not None:
                s.writeInitPlan(init_plan)
            if remove_plan is not None:
                s.writeRemovePlan(remove_plan)
            if self.effective_kernel is not None:
                s.writeEffectiveKernel(self.effective_kernel, [u.id for u in installed])
        except Exception:
            logging.warning("Unable to write out status files")
            logging.debug(traceback.format_exc())
            return False

        if (self.client_config.allow_net and
             (not res or not res.code or res.code not in
               (ERROR_NO_NETWORK,
                ERROR_INVALID_KEY,
                ERROR_MISSING_KEY))):
            logging.debug("Sending result to server.")
            try:
                if res is not None:
                    s.sendResultToServer(self.client_config)
            except Exception:
                logging.warning("Unable to send status to management server")
                logging.debug(traceback.format_exc())
                return False
        return True

    def readInitPlan(self):
        return self.readPlan('init')

    def readRemovePlan(self):
        return self.readPlan('remove')

    def readUpgradePlan(self):
        return self.readPlan('upgrade')

class PackageList(object):
    def __init__(self, text):
        pl = yaml_load(text)
        self.package_list_yaml = pl
        self.error = None

        self.protocolVersion = None
        self.kspliceToolsApiVersion = None
        self.release = None
        self.version = None
        self.arch = None
        self.clientVersionToInstall = '0'
        self.clientVersionToParse = '0'

        self.protocolVersion = pl['Protocol version']
        self.kspliceToolsApiVersion = pl['Client']['Ksplice Tools API version']
        kern = pl['Kernel']
        self.release, self.version, self.arch = \
            kern['Release'], kern['Version'], kern['Architecture']

        self.clientVersionToParse   = pl['Client'].get('Version to Parse', '0')
        self.clientVersionToInstall = pl['Client'].get('Version to Install', '0')

        self.ids = []
        self.packageData = {}
        for item in pl['Updates']:
            self.ids.append(item['ID'])
            self.packageData[item['ID']] = item

def download(c, url, filename, ifmodified=True, stringio=None):
    """Downloads a file to disk with PycURL.

`c` - A pycurl.Curl() object. You probably want getCurl().
`url` - URL to download.
`filename` - Filename to download to.
`ifmodified` - If `filename` exists, only re-download it if the server's
               copy of `url` is newer (i.e., do the If-Modified-Since / 304
               Not Modified thing).
`stringio` - A (c)StringIO object that will be used to read content
             from the server. This can be useful if a caller needs the
             content of the response even if the server doesn't return
             a 200 OK.

Returns the HTTP response code; if you want more information, use
c.getinfo().

Raises non-ENOENT errors from os.stat, and any error from pycurl.
"""
    try:
        if ifmodified:
            try:
                t = int(os.stat(filename).st_mtime)
                c.setopt(pycurl.TIMEVALUE, t)
                c.setopt(pycurl.TIMECONDITION, pycurl.TIMECONDITION_IFMODSINCE)
            except OSError, e:
                if e.errno != errno.ENOENT:
                    raise

        if stringio:
            s = stringio
        else:
            s = StringIO.StringIO()
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.HTTPGET, 1)
        c.setopt(pycurl.WRITEFUNCTION, s.write)
        c.perform()

        rcode = c.getinfo(pycurl.RESPONSE_CODE)
        if rcode == 200:
            mkdirp(os.path.dirname(filename))
            try:
                write_file(filename, s.getvalue())

            except Exception, e:
                # If the entire file didn't get written, try not to leave a
                # partial copy
                try:
                    os.remove(filename)
                except OSError, ee:
                    if ee.errno != errno.ENOENT:
                        raise ee
                raise e

            t = c.getinfo(pycurl.INFO_FILETIME)
            if t > 0:
                os.utime(filename, (t, t))
        elif rcode >= 400 and rcode != 404:
            logging.debug("The server returned error code %d:", rcode)
            logging.debug(s.getvalue())

        return rcode
    finally:
        c.setopt(pycurl.TIMECONDITION, pycurl.TIMECONDITION_NONE)

class UptrackConfig(object):
    def __init__(self):
        self.sysname, self.orig_hostname, self.release, self.version, self.arch, self.userarch = getUname()
        self.hostname = None

        config = ConfigParser.SafeConfigParser()
        try:
            config.read([UPTRACK_CONFIG_FILE])
        except ConfigParser.Error, e:
            raise ResultException(1, "Unable to parse config file: " + e.message)
        self.config = config

        self.setMisc()
        self.setProxy()
        self.setSSL()
        self.setRepoPaths()
        self.setCPUInfo()
        self.setModules()
        self.setVMInfo()
        self.setIP()

        self.removableModules = None

    def setCPUInfo(self):
        sockets = {}
        processors = 0
        try:
            for line in open("/proc/cpuinfo").readlines():
                if line.startswith("physical id"):
                    pid = line.split(":")[1][1:]
                    if pid in sockets:
                        sockets[pid] += 1
                    else:
                        sockets[pid] = 1
                if line.startswith("processor\t"):
                    processors += 1
        except IOError:
            logging.debug(traceback.format_exc())
            self.cpuinfo = [0, 0]
        else:
            if sockets == {}:
                # Virtual machine with no physical processors
                self.cpuinfo = [0, processors]
            else:
                self.cpuinfo = [len(sockets.keys()), sum(sockets.values())]

    def setModules(self):
        self.modules = []
        try:
            for line in open("/proc/modules").readlines():
                (name, size) = line.split()[0:2]
                if name.startswith("ksplice"):
                    continue
                self.modules.append([name, size])
        except IOError:
            logging.debug(traceback.format_exc())
        self.modules.sort()

    def newUUID(self):
        uuid = None
        try:
            proc = subprocess.Popen(['uuidgen'], stdout=subprocess.PIPE)
            uuid = proc.communicate()[0].strip()
        except subprocess.CalledProcessError:
            raise ResultException(1, "Unable to generate a new Uptrack UUID.")

        try:
            mkdirp(os.path.dirname(UPTRACK_UUID_FILE))
            write_file(UPTRACK_UUID_FILE, uuid + "\n")
        except (IOError, OSError), e:
            raise ResultException(1, "Unable to write the Uptrack UUID file " +
                                  UPTRACK_UUID_FILE + ":\n " + str(e))
        return uuid

    def regenerateCron(self):
        p = subprocess.Popen(['/usr/lib/uptrack/regenerate-crontab'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        output, _ = p.communicate()
        if p.returncode != 0:
            logging.debug("Error regenerating crontab.")
            logging.debug(output)
        try:
            os.unlink(os.path.join(self.localroot, 'backoff-counter'))
            os.unlink(os.path.join(self.localroot, 'backoff'))
        except OSError:
            pass

    def updateBackoff(self, backoff):
        try: old = read_file(self.localroot+'/backoff')
        except IOError:
            old = None
        if old != str(backoff)+'\n':
            write_file(self.localroot+'/backoff', str(backoff)+'\n')
            write_file(self.localroot+'/backoff-counter',
                       str(random.randrange(0, backoff))+'\n')

    def configureHostname(self):
        """
        Adjust `hostname` if hostname_override_file is set, and set `fullhostname`.
        """
        if self.config.has_option('Settings', 'hostname_override_file'):
            hostname_override_file = self.config.get('Settings', 'hostname_override_file')
            try:
                self.fullhostname = self.hostname = read_file(hostname_override_file).strip()
                if not self.hostname:
                    logging.error("You must supply a non-empty hostname.")
                    logging.error("Please check the hostname_override_file option in /etc/uptrack/uptrack.conf.")
                    sys.exit(1)
            except (IOError, OSError):
                logging.error("Unable to read hostname from %s." % (hostname_override_file,))
                logging.error("Please check the hostname_override_file option in /etc/uptrack/uptrack.conf.")
                sys.exit(1)
        else:
            self.hostname = self.orig_hostname
            try:
                self.fullhostname = socket.gethostbyaddr(self.hostname)[0]
            except socket.error:
                self.fullhostname = ''

    def setMisc(self):
        self.lockfile = "/var/lib/uptrack/lock"
        self.accesskey = ""
        if self.config.has_option('Auth', 'accesskey'):
            self.accesskey = self.config.get('Auth', 'accesskey')
        self.uuid = None

        self.newuuid = None
        self.olduuid = None

        self.debug_to_server = getConfigBooleanOrDie(
            self.config, 'Settings', 'debug_to_server', True)

        self.use_hw_uuid = getConfigBooleanOrDie(
            self.config, 'Auth', 'use_hw_uuid', False)

        self.no_rmmod = getConfigBooleanOrDie(
            self.config, 'Settings', 'no_rmmod', False)

        self.run_uuid = None
        self.run_uuid_error = None
        try:
            p = subprocess.Popen(['uuidgen'], stdout=subprocess.PIPE)
            self.run_uuid = p.communicate()[0].strip()
        except subprocess.CalledProcessError:
            self.run_uuid_error = traceback.format_exc()

    def initWithLock(self):
        # Note! This is not called by __init__, because UptrackConfig is not
        # initialized under the repository lock. This must be called separately
        # once the lock is held.
        self.serial = 0
        self.serial_stat = None
        uuid = None

        if self.use_hw_uuid:
            uuid = self.vminfo.get('uuid').lower()
            if uuid == '00000000-0000-0000-0000-000000000000':
                uuid = None

        if uuid is None:
            try:
                uuid = read_file(UPTRACK_UUID_FILE).strip()
                try:
                    self.serial = int(read_file(UPTRACK_SERIAL_FILE).strip())
                except ValueError:
                    self.serial_stat = tuple(os.stat(UPTRACK_SERIAL_FILE))
            except (IOError, OSError):
                pass

        if not uuid:
            uuid = self.newUUID()
        self.setUUID(uuid)
        self.configureHostname()

    def incrementSerial(self):
        """ Increment self.serial and write the result to disk.

        Returns the previous serial number.
        """
        old = self.serial
        self.serial += 1
        try:
            tmp_serial_file = UPTRACK_SERIAL_FILE + ".tmp"
            write_file(tmp_serial_file, "%d\n" % (self.serial,))
            os.rename(tmp_serial_file, UPTRACK_SERIAL_FILE)
        except (IOError, OSError), e:
            logging.debug("Unable to store new serial", exc_info=True)
            raise ResultException(1,
                                  "Unable to increment the Uptrack serial number (%s):\n%s"
                                  % (UPTRACK_SERIAL_FILE, e))

        return old

    def setProxy(self):
        """ Set self.proxy based on config and the environment.

        Set self.proxy to the value of a proxy server to use to talk to the
        Uptrack server, based on the config file, the envrionment, and the
        global GConf database if available.

        Upon return, self.proxy will be set in one of three ways:

        - None: No proxy setting was detected. Uptrack will let pycurl attempt
                to choose a proxy based on its own defaults.
        - '':   The user explicitly requested that no proxy be used. Uptrack will
                force pycurl not to use a proxy.
        - Any other string: The URL of an HTTPS proxy server to use with
                the CONNECT method.

        In order to allow the user to explicitly specify "no proxy" globally, we
        accept the value 'none' (case insensitive) in the Network.https_proxy
        setting in uptrack.conf, and translate it to self.proxy = ''. An empty
        setting is taken to be unset, and will result in self.proxy being None.

        (Note that, confusingly, this means that "Network.https_proxy = none"
         corresponds to self.proxy = '', and vice versa.)
        """
        self.proxy = None
        if self.config.has_option('Network', 'https_proxy'):
            proxy = self.config.get('Network', 'https_proxy').strip()
            if proxy:
                if proxy.lower() == 'none':
                    self.proxy = ''
                else:
                    self.proxy = proxy
                return

        for key in ['https_proxy', 'HTTPS_PROXY', 'http_proxy']:
            if key in os.environ:
                self.proxy = os.environ[key]
                return

        # default to True to preserve behavior of old config files
        enable_gconf = getConfigBooleanOrDie(
            self.config, 'Network', 'gconf_proxy_lookup', True)

        if not (have_gconf and enable_gconf):
            return

        try:
            client = gconf.client_get_default()
            if client.get_bool('/system/http_proxy/use_http_proxy'):
                host = client.get_string('/system/http_proxy/host')
                port = client.get_int('/system/http_proxy/port')
                self.proxy = 'http://' + host + ":" + str(port)
        except Exception:
            pass

    def setSSL(self):
        self.ssl_ca_certs = []
        if self.config.has_option('Network', 'ssl_ca_cert_file'):
            self.ssl_ca_certs.append((pycurl.CAINFO,
                                      self.config.get('Network', 'ssl_ca_cert_file')))
        if self.config.has_option('Network', 'ssl_ca_cert_dir'):
            self.ssl_ca_certs.append((pycurl.CAPATH,
                                      self.config.get('Network', 'ssl_ca_cert_dir')))

    def setRepoPaths(self):
        self.localroot = UPTRACK_CACHE_DIR
        self.local = os.path.join(self.localroot,
                                  self.sysname,
                                  self.arch,
                                  self.release,
                                  self.version)
        self.remoteroot = UPDATE_REPO_URL
        if self.config.has_option("Network", "update_repo_url"):
            remote = self.config.get("Network", "update_repo_url").strip()
            if remote:
                self.remoteroot = remote

    def setUUID(self, uuid):
        self.uuid = uuid
        self.remote = posixpath.join(self.remoteroot,
                                     urllib.quote(self.accesskey),
                                     "+uuid", urllib.quote(self.uuid))

    def setVMInfo(self):
        if not hasattr(self, 'vminfo'):
            self.vminfo = getVMInfo()

    def setIP(self):
        """
        Set localip to a dictionary of the form {"IP": "X.X.X.X"}.

        If the suppress_ip config option is enabled, set a dummy
        address. Otherwise, try to get it from the 'ip' command. Upon failure,
        set localip to an error dict of the form {"Error": "error_msg"} instead.
        """
        if getConfigBooleanOrDie(self.config, 'Settings', 'suppress_ip', False):
            self.localip = {"IP": "0.0.0.0"}
            return

        try:
            proto = rest = hostport = path = userinfo = netloc = port = host = None

            uri = self.remoteroot
            if self.proxy:
                uri = self.proxy
            (proto, rest) = urllib.splittype(uri)

            # Curl accepts a proxy without leading http(s)://, which
            # requires special processing here.
            if self.proxy and not rest.startswith("//"):
                (proto, rest) = urllib.splittype("http://" + uri)

            if rest:
                (netloc, path) = urllib.splithost(rest)
            if netloc:
                (userinfo, hostport) = urllib.splituser(netloc)
            if hostport:
                (host, port) = urllib.splitport(hostport)
            if host:
                remoteip = socket.gethostbyname(host)
                p = subprocess.Popen(['ip', 'route', 'get', remoteip],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                routedata = p.communicate()[0]
                if ' src ' in routedata:
                    self.localip = {'IP': routedata[routedata.index(' src '):].split()[1]}
                else:
                    self.localip = {'Error': "Could not parse IP address from route data (%s)" % routedata}
            else:
                self.localip = {'Error': "Could not parse hostname out of remote or proxy (%s)" % uri}
        except Exception, e:
            self.localip = {'Error': "%s (host = %s, uri = %s)" % (str(e), host, uri)}

def inVirtualBox():
    # PCI ID 0x80ee is VirtualBox virtual devices
    # http://pci-ids.ucw.cz/read/PC/80ee
    try:
        for line in file('/proc/bus/pci/devices', 'r'):
            fields = line.split()
            if fields[1][0:4] == '80ee':
                return True
    except (IOError, IndexError):
        pass
    return False

def getVMInfo():
    """Find the UUID of this machine and of any VMs it is hosting."""
    vminfo = {}
    devnull = open('/dev/null', 'w')

    # On a Xen paravirt domU, you get the UUID from /sys/hypervisor/uuid.
    # On most other systems (dom0, HVM domU, bare hardware, most other
    # virtualization systems) you get the UUID from DMI, but accessing DMI
    # fails on a Xen paravirt domU. So we check /sys/hypervisor first.

    # Reading /sys/hypervisor/uuid hangs if xenstored hasn't started yet.
    # See https://bugzilla.redhat.com/show_bug.cgi?id=225203
    # So instead we spin off a child process to do the read, such that
    # it's okay if it hangs.
    try:
        proc = subprocess.Popen(['cat', '/sys/hypervisor/uuid'],
                                stdout=subprocess.PIPE, stderr=devnull)
    except subprocess.CalledProcessError, e:
        vminfo['xen_error'] = str(e)
    else:
        if select.select([proc.stdout], [], [], 1)[0]:
            if proc.wait() == 0:
                vminfo['uuid'] = proc.stdout.read().strip()
            # else: not Xen
        else:
            vminfo['xen_error'] = 'Read of /sys/hypervisor/uuid timed out; is xenstored running?'

    if vminfo.get('uuid') == '00000000-0000-0000-0000-000000000000':
        vminfo['type'] = 'Xen dom0'
        del vminfo['uuid']
        try:
            proc = subprocess.Popen(['xenstore-list', '/vm'],
                                    stdout=subprocess.PIPE, stderr=devnull)
            vminfo['children'] = proc.communicate()[0].strip().split('\n')
            try:
                vminfo['children'].remove('00000000-0000-0000-0000-000000000000')
            except ValueError:
                pass
            if proc.wait():
                vminfo['xen_error'] = 'xenstore-list /vm returned %d' % proc.returncode
        except (IOError, OSError, subprocess.CalledProcessError), e:
            vminfo['xen_error'] = str(e)
    elif 'uuid' in vminfo:
        vminfo['type'] = 'Xen paravirt domU'

    # Checks for other virtualization systems would go here

    if 'uuid' not in vminfo:
        try:
            # Bare metal, or Xen HVM domU, or VMware, or KVM
            proc = subprocess.Popen(['dmidecode', '-t', 'system'],
                                    stdout=subprocess.PIPE, stderr=devnull)
            for line in proc.communicate()[0].split('\n'):
                s = line.split("UUID: ", 1)
                if len(s) > 1:
                    vminfo['uuid'] = s[1]
                s = line.split("Product Name: ", 1)
                if len(s) > 1:
                    # "HVM domU" is the most interesting value here, but
                    # no harm in fetching this value unconditionally (it
                    # shows up in oopses, for instance)
                    vminfo.setdefault('type', s[1])
            if proc.wait():
                vminfo['dmidecode_error'] = 'dmidecode -t system returned %d' % proc.returncode
        except (IOError, OSError, subprocess.CalledProcessError), e:
            vminfo['dmidecode_error'] = str(e)

    try:
        vminfo['num_containers'] = len(file("/proc/vz/veinfo").readlines())
    except:
        vminfo['num_containers'] = 0

    return vminfo

def getMmapMinAddr():
    """Return the value of `mmap_min_addr` on this machine."""
    try:
        mmap_min_addr = read_file('/proc/sys/vm/mmap_min_addr').strip()
    except:
        mmap_min_addr = None

    return mmap_min_addr
