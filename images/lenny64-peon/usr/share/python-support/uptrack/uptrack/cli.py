#!/usr/bin/env python

# Copyright (C) 2008-2011  Ksplice, Inc.
# Authors: Waseem Daher and Tim Abbott
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
#
# Not a Contribution for purposes of the Fedora Project Individual Contributor
# License Agreement

import sys
# Disable Launchpad's apport traceback hooks
sys.excepthook = sys.__excepthook__

# Add our own Python directories to the start of the Python library path
sys.path[:0] = ['/usr/lib/uptrack/lib/python2.%s/site-packages' % sys.version_info[1],
                '/usr/lib/uptrack/lib64/python2.%s/site-packages' % sys.version_info[1]]

import fcntl
import urllib
import urlparse
import posixpath
import os
import pwd
import grp
import errno
import shutil
import tempfile
import time
import logging
import logging.handlers
import yaml
import random
import textwrap
import signal
import cStringIO as StringIO
from optparse import OptionParser, SUPPRESS_HELP

## Special handling for modules that didn't
## exist in Python 2.3 and Python 2.4
try: import hashlib
except ImportError: import hashlib_compat as hashlib

if sys.version_info >= (2, 6, 2, 'final', 0):  # subprocess_compat comes from 2.6.2
    import subprocess
else:
    import subprocess_compat as subprocess

try: set
except NameError: from sets import Set as set

import traceback
try: traceback.format_exc
except AttributeError:
    def traceback_format_exc(limit=None):
        """Like print_exc() but return a string."""
        try:
            etype, value, tb = sys.exc_info()
            return ''.join(traceback.format_exception(etype, value, tb, limit))
        finally:
            etype = value = tb = None
    traceback.format_exc = traceback_format_exc

# Special handling for old versions of pycurl
import pycurl
try: pycurl.E_COULDNT_RESOLVE_PROXY
except:
    # Values from an enum in include/curl/curl.h.  Comments in that
    # header say these should never change, so it seems reasonably
    # safe to use them on old versions of pycurl where these constants
    # are not exported to Python.
    pycurl.E_COULDNT_RESOLVE_PROXY = 5
    pycurl.E_COULDNT_RESOLVE_HOST = 6
    pycurl.E_COULDNT_CONNECT = 7
    pycurl.E_OPERATION_TIMEOUTED = 28
    pycurl.E_URL_MALFORMAT = 3
    pycurl.E_SSL_CACERT = 60


## Specially deal with dbus
have_dbus = 0
try:
    import dbus
    import dbus.service
    import dbus.mainloop.glib
    if dbus.version >= (0, 80, 0):
        from dbus.mainloop.glib import DBusGMainLoop
        DBusGMainLoop(set_as_default=True)
    dbus.SystemBus()
    have_dbus = 1
except Exception:
    pass

import Uptrack
import UptrackDepSolver
__version__ = Uptrack.__version__
LOGFILE='/var/log/uptrack.log'
LOGUSER='root'
LOGGROUP='adm'
LOGMODE=0640
KEYRING='/usr/share/uptrack/uptrack.gpg'
UPTRACK_GPG_HOMEDIR='/etc/uptrack'
SERVER_KEYRING='/usr/share/uptrack/uptrack-server.gpg'
SERVER_KEY_FINGERPRINT="9C99586684B64DE53F0885700EE0EADBD74EE7FC"
API_VERSION_FILE="/usr/share/uptrack/ksplice-tools-api-version"
KSPLICE_DEBUG_FILE='/var/run/ksplice/debug'
DEPMOD_NEEDED_FILE=os.path.join(Uptrack.UPTRACK_CACHE_DIR, "depmod-needed")
UPTRACK_PACKAGES_PROTOCOL_VERSION='2'
CODE_BUSY_RETRIES = 2 # for a total of 3 tries
CODE_BUSY_MAX_DELAY = 5.0 # seconds
MAX_RETRIES = CODE_BUSY_RETRIES + 1 # 1 for trying to remove modules

# What should this be?
HTTP_CODE_EXPIRED = 420

# The number of seconds to wait before giving up on acquiring the
# repository lock.
LOCK_TIMEOUT = 10

INIT='Init'
UPGRADE='Upgrade'

# Note: We depend on these constants having these particular values,
# because they occasionally get shown directly to users. (Probable
# future i18n implications here)
INSTALL='Install'
REMOVE='Remove'
SHOW='Show'

AUTOGEN_FLAG_FILE='/var/lib/uptrack/autogen'
AUTOGEN_URL='https://updates.ksplice.com/cgi/code.pl?terms=1&noninteractive=1&noemail=1'
TOS_FILE='/usr/share/doc/uptrack/tos'

alert = None
desupported = False
tray_icon_error = None

config = None
local = None
lock = None
repo = None


def makeUpdate(item, local_dir, remote_dir, order):
    return Update(local_dir = local_dir,
                  remote_dir = remote_dir,
                  id = item['ID'],
                  filename = item['Filename'],
                  name = item['Name'],
                  hash = item['SHA-1'],
                  targets = item['Targets'],
                  order = order)

def toModuleName(filename):
    # Logic matches smells_like_module from module-init-tools' depmod.c.
    if filename[-3:] != '.ko' and filename[-6:] != '.ko.gz':
        return None
    # Logic matches filename2modname from module-init-tools' modprobe.c.
    return os.path.basename(filename).split('.')[0].replace('-', '_')

def getLoadedModules():
    p = subprocess.Popen(['lsmod'],
                         stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode:
        logging.error("Error in lsmod")
        if stdout:
            logging.debug("stdout:")
            logging.debug(stdout)
        if stderr:
            logging.debug("stderr:")
            logging.debug(stderr)
        raise subprocess.CalledProcessError(p.returncode, 'lsmod')

    result = {}
    for l in stdout.strip().split('\n')[1:]:
        fields = l.split(None, 3)
        if len(fields) >= 4:
            usedBy = fields[3].split(',')
        else:
            usedBy = []
        result[fields[0]] = {'Size': fields[1], 'UseCount': fields[2], 'UsedBy': usedBy}
    return result

def rmmod(module):
    """
    Attempt to unload the given module.
    Returns True if successful.
    """
    logging.debug("Trying to rmmod %s" % module)
    p = subprocess.Popen(['rmmod', module], stdout = subprocess.PIPE,
                         stderr = subprocess.STDOUT)
    logging.debug(p.communicate()[0])
    return (p.returncode == 0)

class Update(object):
    def __init__(self, id, name, filename, hash,
                 targets, local_dir, remote_dir,
                 order):
        self.id = id
        self.name = name
        self.filename = filename
        self.hash = hash
        self.targets = targets[:]
        self.local_dir = local_dir
        self.remote_dir = remote_dir
        self.order = order
    def __str__(self):
        return "[%s] %s" % (self.id, self.name)
    def __repr__(self):
        return self.__str__()
    def __eq__(self, other):
        return self.id == other.id
    def __hash__(self):
        return hash(self.id)

    def _remote_path(self):
        return posixpath.join(self.remote_dir, self.filename)
    remote_path = property(_remote_path)

    def _local_path(self):
        return os.path.join(self.local_dir, self.filename)
    local_path = property(_local_path)

    def _tree_path(self):
        return os.path.join(self.local_dir, 'updates', 'ksplice-'+self.id)
    tree_path = property(_tree_path)

    def _tree_flag_path(self):
        return os.path.join(self.local_dir, 'updates', 'ksplice-'+self.id+'.incomplete')
    tree_flag_path = property(_tree_flag_path)

    def checkValidFile(self):
        if not os.path.isfile(self.local_path):
            return Uptrack.Result(1, "Update file does not exist for update %s" % (self.id,))
        try:
            text = Uptrack.read_file(self.local_path, 'rb')
        except IOError:
            logging.debug(traceback.format_exc())
            return Uptrack.Result(1, "Unable to read update file %s" % (self.local_path,))
        hash = hashlib.sha1(text).hexdigest()
        if hash != self.hash:
            logging.debug("%s: invalid checksum: got %s, expected %s"
                          % (self.id, hash, self.hash))
            return Uptrack.Result(1, "Invalid checksum for update %s." % (self.id,))
        if (not os.path.isdir(self.tree_path)
            or os.path.isfile(self.tree_flag_path)):
            return Uptrack.Result(1, "Update %s has not been unpacked." % (self.id,))
        return Uptrack.Result()

    def isValidFile(self):
        return self.checkValidFile().code == 0

    def unpack(self):
        def fix_sigpipe():
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)

        file(self.tree_flag_path, "w")
        shutil.rmtree(self.tree_path, ignore_errors=True)
        p = subprocess.Popen(['tar', '--force-local', '-xzf', self.local_path,
                              '-C', os.path.join(self.local_dir, 'updates')],
                             stdout = subprocess.PIPE, stderr = subprocess.STDOUT,
                             preexec_fn = fix_sigpipe)
        output = p.communicate()[0]
        if p.returncode:
            return Uptrack.Result(p.returncode, output)
        os.unlink(self.tree_flag_path)
        return Uptrack.Result()

    def getDetails(self):
        details = os.path.join(self.tree_path, 'details')
        if not os.path.isfile(details):
            details = os.path.join(self.tree_path, 'patch')
        try:
            return Uptrack.read_file(details)
        except IOError:
            logging.debug("Could not retrieve details from %s" % self)
            logging.debug(traceback.format_exc())
            return ''

    def getCoreVersion(self):
        # update is applied using ksplice standalone
        ksplice_dir = '/sys/module/ksplice_%s/ksplice' % self.id
        if os.path.exists(ksplice_dir):
            core_version_file = os.path.join(ksplice_dir, 'core_version')
            if os.path.exists(core_version_file):
                return Uptrack.read_file(core_version_file)
            else:
                return '0'

        # update is applied using ksplice integrated
        ksplice_dir = '/sys/kernel/ksplice/%s' % self.id
        if os.path.exists(ksplice_dir):
            core_version_file = os.path.join(ksplice_dir, 'core_version')
            if os.path.exists(core_version_file):
                return Uptrack.read_file(core_version_file)
            else:
                return '0'

        # update is not applied, so grab the data from tree_path
        core_version_file = os.path.join(self.tree_path, 'core_version')
        if os.path.exists(core_version_file):
            return Uptrack.read_file(core_version_file)
        else:
            return '0'

    def lockedModules(self):
        locked = []
        modules = getLoadedModules()
        targets = [toModuleName(x) for x in self.targets]
        for t in targets:
            if t in modules and 'ksplice_%s_%s_new' % (self.id, t) not in modules:
                locked.append(t)
        return locked

    def isLocked(self):
        return len(self.lockedModules()) != 0


    def runKspliceCommand(self, command, args):
        res = Uptrack.ActionResult(self, command)
        p = subprocess.Popen(args,
                             stdout = subprocess.PIPE,
                             stderr = subprocess.STDOUT)

        output = p.communicate()[0]
        if p.returncode == 0:
            return res

        Uptrack.mkdirp(os.path.dirname(KSPLICE_DEBUG_FILE))
        p = subprocess.Popen(args + ['--debugfile', KSPLICE_DEBUG_FILE, "--raw-errors"],
                             stdout = subprocess.PIPE,
                             stderr = subprocess.PIPE)
        lines = p.communicate()[1].split("\n")
        if p.returncode == 0:
            # Cool, it worked this time.
            try:
                os.remove(KSPLICE_DEBUG_FILE)
            except OSError:
                pass
            return res

        res.code = p.returncode
        res.abort_code = lines[0]
        res.message = output
        try:
            res.debug = Uptrack.read_file(KSPLICE_DEBUG_FILE)
        except IOError:
            pass

        if res.abort_code == 'code_busy':
            res.stack_check_processes = [line.split(" ") for line in lines[1:] if len(line.strip())]
        elif res.abort_code == 'cold_update_loaded':
            res.locked_modules = self.lockedModules()
        elif res.abort_code == 'failed_to_find' or res.abort_code == 'no_match':
            # Compute the list of modules loaded and affected by this
            # upgrade, for later display

            res.nomatch_modules = []

            # This code is a bit of a hack because Ksplice itself
            # doesn't export which module was responsible for the
            # failure
            target_modules = [toModuleName(x) for x in self.targets]

            logging.debug("Run/pre matching failed; targets were:")
            logging.debug(target_modules)

            res.nomatch_modules = list(set(getLoadedModules()).intersection(target_modules))

            logging.debug("Loaded target modules were:")
            logging.debug(res.nomatch_modules)
        elif res.abort_code == 'module_busy':
            usedby_modules = set()
            
            for modname, modinfo in getLoadedModules().items():
                if modname == 'ksplice_' + self.id or modname.startswith('ksplice_' + self.id + '_'):
                    usedby_modules |= set([d for d in modinfo['UsedBy'] if not d.startswith('ksplice_')])

            res.usedby_modules = list(usedby_modules)

        return res

    def shouldRetry(self, res, duration, retryData):
        """
        Logic for deciding whether to retry a runKspliceCommand.

        'retryData' is a dict which stores information on the number
        of times we have retried the command due to various causes.
        The caller can pass a new empty dict the first time it tries
        to execute a given command.

        shouldRetry() returns one of the strings 'Success', 'Failure',
        or 'Retry'.  In the 'Retry' case, the 'retryData' argument
        will have been modified to reflect the retry that occurred.
        """

        if 'DidRfcommRetry' not in retryData:
            # Have we tried to rmmod rfcomm and then retry?
            retryData['DidRfcommRetry'] = False
        if 'CodeBusyRetries' not in retryData:
            # number of previous retries due to other code_busy results
            retryData['CodeBusyRetries'] = 0
        if 'RemoveModulesRetries' not in retryData:
            # number of previous retries due to no_match/failed_to_find
            retryData['RemoveModulesRetries'] = 0

        if not res.code:
            return 'Success'
        elif res.abort_code == 'code_busy':
            rfcomm_stack_check = 'krfcommd' in [proc[0] for proc in res.stack_check_processes]
            if rfcomm_stack_check and not retryData['DidRfcommRetry']:
                logging.debug("Stack check against rfcomm module; trying to remove")
                rmmod('rfcomm')
                time.sleep(1)
                retryData['DidRfcommRetry'] = True
                return 'Retry'
            elif duration > CODE_BUSY_MAX_DELAY:
                logging.debug("Slow stack check failure")
                return 'Failure'
            elif retryData['CodeBusyRetries'] < CODE_BUSY_RETRIES:
                logging.debug("Stack check failure %d, retrying" % (retryData['CodeBusyRetries'] + 1))
                time.sleep(1)
                retryData['CodeBusyRetries'] += 1
                return 'Retry'
            else:
                return 'Failure'
        elif res.abort_code in ['no_match', 'failed_to_find'] \
                and retryData['RemoveModulesRetries'] < 1 and config.removableModules:
            loadedModules = getLoadedModules()
            # Preserve the order of config.removableModules,
            # which is the correct order to remove the modules in
            removableModules = [m for m in config.removableModules if m in loadedModules]
            modulesRemoved = []
            if not config.no_rmmod:
                for module in removableModules:
                    if rmmod(module):
                        modulesRemoved += [module]
            if modulesRemoved:
                logging.debug("Removed modules " + str(modulesRemoved) + ", retrying")
                retryData['RemoveModulesRetries'] += 1
                return 'Retry'
            else:
                return 'Failure'
        else:
            return 'Failure'

    def applyUpdate(self):
        cmd = INSTALL

        r = self.checkValidFile()
        if r.code:
            res = Uptrack.ActionResult(self, cmd)
            res.code = r.code
            res.message = r.message
            return res

        retryData = {}
        for previousRetries in range(0, MAX_RETRIES + 1):
            starttime = time.time()
            res = self.runKspliceCommand(cmd,
                      ['/usr/lib/uptrack/ksplice-apply', '--partial', self.tree_path])
            endtime = time.time()
            cont = self.shouldRetry(res, endtime - starttime, retryData)
            if cont == 'Success':
                break
            elif cont == 'Retry' and previousRetries < MAX_RETRIES:
                pass # retry
            else:
                return res

        # finally, on-disk application
        if not self.targets:
            res.depmod_needed = False
            return res
        modroot = "/var/run/ksplice/modules/%s" % config.release
        backupdir = "/var/run/ksplice/modules.old/%s" % config.release
        moddir = os.path.join(modroot, "ksplice")
        Uptrack.mkdirp(moddir)
        Uptrack.mkdirp(backupdir)
        targets = set([toModuleName(x) for x in self.targets])
        try:
            update_modroot = os.path.join(self.tree_path, 'modules')
            for dirname, _, filenames in os.walk(update_modroot):
                for filename in filenames:
                    target = toModuleName(filename)
                    if target is None or target not in targets:
                        continue
                    targets.discard(target)
                    modpath = ("%s/ksplice/%s.ko" % (modroot, target))
                    if os.path.isfile(modpath):
                        backup = os.path.join(backupdir,
                                              "%s_pre_%s.ko" % (target, self.id))
                        os.rename(modpath, backup)
                    os.symlink(os.path.join(update_modroot, dirname, filename),
                               modpath)
        except IOError:
            res.code = 1
            res.message = "Failure in extracting modules from %s" % self
            logging.debug(res.message)
            logging.debug(traceback.format_exc())
            return res
        if targets:
            res.code = 1
            res.message = ("Could not retrieve some modules from %s:\n" % self
                           + " missing " + " ".join(targets))
            logging.debug(res.message)
            return res

        depmod_dir = "/var/run/ksplice/depmod.d"
        Uptrack.mkdirp(depmod_dir)
        for target in [toModuleName(x) for x in self.targets]:
            depmod_file = "%s/%s.conf" % (depmod_dir, target)
            if not os.path.exists(depmod_file):
                entry = ("override %s %s.ksplice-updates ksplice\n"
                         % (target, config.release))
                logging.debug("Adding new depmod entry: %s" % entry.strip())
                Uptrack.write_file(depmod_file, entry)
        res.depmod_needed = True
        return res

    def undoUpdate(self):
        cmd = REMOVE

        retryData = {}
        for previousRetries in range(0, MAX_RETRIES + 1):
            starttime = time.time()
            res = self.runKspliceCommand(cmd,
                      ['/usr/lib/uptrack/ksplice-undo', self.id])
            endtime = time.time()
            cont = self.shouldRetry(res, endtime - starttime, retryData)
            if cont == 'Success':
                break
            elif cont == 'Retry' and previousRetries < MAX_RETRIES:
                pass # retry
            else:
                return res

        # Reverse on-disk application
        if not self.targets:
            res.depmod_needed = False
            return res
        depmod_dir = "/var/run/ksplice/depmod.d"
        modroot = "/var/run/ksplice/modules/%s" % config.release
        backupdir = "/var/run/ksplice/modules.old/%s" % config.release
        for target in [toModuleName(x) for x in self.targets]:
            depmod_file = "%s/%s.conf" % (depmod_dir, target)
            modpath = "%s/ksplice/%s.ko" % (modroot, target)
            backup = os.path.join(backupdir, "%s_pre_%s.ko" % (target, self.id))
            if os.path.isfile(modpath):
                os.remove(modpath)
            else:
                logging.warning("Missing patched module %s while undoing %s"
                                % (modpath, self.id))
            if os.path.isfile(backup):
                try:
                    os.rename(backup, modpath)
                except IOError:
                    logging.warning("Failed to restore old module %s -> %s" %
                                    (backup, modpath))
                    logging.debug(traceback.format_exc())
                # Don't remove the depmod entry, since someone is using it
            elif os.path.isfile(depmod_file):
                try:
                    logging.debug("Removing depmod entry: %s" % Uptrack.read_file(depmod_file).strip())
                    os.remove(depmod_file)
                except IOError:
                    logging.warning("Failed to remove depmod file %s" %
                                    (depmod_file,))
                    logging.debug(traceback.format_exc())
            else:
                logging.warning("Missing depmod override file %s while undoing %s"
                                % (depmod_file, self.id))
        res.depmod_needed = True
        return res

def kspliceToolsApiVersion():
    if os.path.exists(API_VERSION_FILE):
        return Uptrack.read_file(API_VERSION_FILE).strip()
    return '-1'

def serverFingerprint(url):
    try:
        netloc = urlparse.urlparse(url)[1]
        if ':' not in netloc:
            netloc += ":443"
        conn = subprocess.Popen(['openssl', 's_client', '-connect', netloc],
                                stdin=open('/dev/null'),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        x509 = subprocess.Popen(['openssl', 'x509', '-fingerprint', '-sha1'],
                                stdin=conn.stdout,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        x509.wait()
        for line in x509.stdout:
            if line.startswith("SHA1 Fingerprint="):
                return line[len("SHA1 Fingerprint="):].strip()
    except subprocess.CalledProcessError:
        logging.debug("Error reading server certificate fingerprint.")
        logging.debug(conn.stderr.read())
        logging.debug(x509.stderr.read())
        return None
    return None

class UptrackRepo(object):
    def __init__(self, config):
        self.updates = None
        self.protocolVersion = UPTRACK_PACKAGES_PROTOCOL_VERSION
        self.remote_dir = posixpath.join(config.remote,
                                         urllib.quote(config.sysname),
                                         urllib.quote(config.arch),
                                         urllib.quote(config.release),
                                         urllib.quote(config.version))
        self.local_dir = config.local
        self.local_package_list = os.path.join(self.local_dir, "packages.yml")
        self.kspliceToolsApiVersion = kspliceToolsApiVersion()
        self.clientVersion = __version__
        self.userStatus = None
        self.expired = False



    def verifyKeyring(self, keyring, fingerprint):
        logging.debug("Verifying key fingerprint...")
        p = subprocess.Popen(['gpg',
                              '--no-options',
                              '--homedir', UPTRACK_GPG_HOMEDIR,
                              '--no-default-keyring',
                              '--batch',
                              '--keyring', keyring,
                              '--fingerprint',
                              '--with-colons'],
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE)
        stdout, stderr = p.communicate()
        if stdout: logging.debug(stdout)
        if stderr: logging.debug(stderr)
        if p.returncode:
            return Uptrack.Result(1, "Ksplice Uptrack failed to read fingerprint")
        listings = [l.split(':') for l in stdout.strip().split("\n")]
        fprs = [l for l in listings if l[0] == "fpr"]
        if len(fprs) < 1:
            return Uptrack.Result(1, "Ksplice Uptrack could not find any fingerprints")
        if len(fprs) > 1:
            return Uptrack.Result(1, "Ksplice Uptrack found too many fingerprints")
# 10. Field:  User-ID.  [..]
#             An FPR record stores the fingerprint here.
#             The fingerprint of an revocation key is stored here.
        if fprs[0][9] != fingerprint:
            return Uptrack.Result(1, "Ksplice Uptrack could not verify the key fingerprint")
        logging.debug("Verified GPG fingerprint on %s", keyring)
        return None

    def validateServer(self):
        if config.remoteroot == Uptrack.UPDATE_REPO_URL:
            return None

        res = self.verifyKeyring(SERVER_KEYRING, SERVER_KEY_FINGERPRINT)
        if res:
            return res

        fingerprint = serverFingerprint(config.remoteroot)
        logging.debug("Got a server fingerprint: %s", fingerprint)

        if fingerprint is None:
            return Uptrack.Result(
                Uptrack.ERROR_NO_NETWORK,
                "Unable to communicate with your site's Uptrack server.\n\n"
                "Please ensure that the update_repo_url setting is correct in\n"
                "/etc/uptrack/uptrack.conf, and that your Uptrack server is properly configured.\n"
                "If you need help resolving this issue, please contact %s."
                % (Uptrack.BUG_EMAIL,))

        sigpath = os.path.join(config.localroot, fingerprint + ".sig")
        try:
            code = Uptrack.download(Uptrack.getCurl(),
                                    posixpath.join(config.remoteroot,
                                                   'server',
                                                   fingerprint + ".sig"),
                                    sigpath)
            if code not in (200, 304):
                return Uptrack.Result(
                    1,
                    "Unable to download the signature for your Uptrack server.\n"
                    "Please contact %s for assistance." % (Uptrack.BUG_EMAIL,))
        except pycurl.error, e:
            logging.debug("cURL error %d (%s) while checking server signature."
                          % (e[0], e[1]))
            logging.debug(traceback.format_exc())
            return Uptrack.resultFromPycurl(config, e)

        fpfile = None
        try:
            (fd, fpfile) = tempfile.mkstemp()
            fh = os.fdopen(fd, 'w')
            fh.write(fingerprint + "\n")
            fh.close()
            if not self.verifySignature(fpfile, sigpath, keyring=SERVER_KEYRING):
                return Uptrack.Result(
                    1,
                    "Unable to verify that the server at <%s>\n"
                    "is an authorized Ksplice Uptrack server. Please contact\n"
                    "Ksplice at <%s> for assistance." %
                    (config.remoteroot, Uptrack.BUG_EMAIL))
        finally:
            try:
                if fpfile:
                    os.unlink(fpfile)
            except OSError:
                pass

        return None


    def downloadUserStatus(self):
        err = None
        key_check = posixpath.join(config.remote,
                                   urllib.quote('status'))
        localpath = os.path.join(config.localroot, 'status')

        logging.debug("Verifying your access key is valid by requesting: %s" % key_check)
        s = StringIO.StringIO()
        try:
            request = dict(Serial=config.incrementSerial())
            Uptrack.Status.addIdentity(config, request)
            contents = Uptrack.yaml_dump(request, version=(1, 1),
                                         explicit_start = True,
                                         explicit_end = True)

            c = Uptrack.getCurl()
            c.setopt(pycurl.URL, key_check)
            c.setopt(pycurl.HTTPPOST, [('request', contents)])
            c.setopt(pycurl.WRITEFUNCTION, s.write)
            c.perform()
            code = c.getinfo(pycurl.RESPONSE_CODE)
            if code == 200 or code == 304:
                try:
                    Uptrack.write_file(localpath, s.getvalue())
                except IOError, e:
                    logging.debug("Error writing status file.")
                    logging.debug(traceback.format_exc())

                try:
                    self.userStatus = Uptrack.yaml_load(s.getvalue())
                except yaml.YAMLError:
                    # Silently ignore malformed YAML for now, since
                    # historically this file wasn't YAML.
                    logging.debug("Malformed YAML response when checking the key.")
                    return None
            elif 400 <= code <= 499:
                logging.debug("Your access key (%s) is invalid." % config.accesskey)
                err = Uptrack.Result(Uptrack.ERROR_INVALID_KEY,
                                     "Could not connect to the Ksplice Uptrack "
                                     "server with your access key.\n"
                                     "Please check that the key in %s is valid.\n" %
                                     Uptrack.UPTRACK_CONFIG_FILE)
            else:
                logging.debug("Unexpected error retrieving status file (%d)", code)
                logging.debug("The server said:")
                logging.debug(s.getvalue())
                if 500 <= code <= 599:
                    err = Uptrack.server_error_exception.result
                else:
                    err = Uptrack.Result(
                        Uptrack.ERROR_INTERNAL_SERVER_ERROR,
                        "Unexpected error communicating with the server.\n"
                        "Please try again in a few minutes. If this problem persists, \n"
                        "please contact %s for assistance." % (Uptrack.BUG_EMAIL,))


        except pycurl.error, e:
            logging.debug("cURL error %d (%s) while checking key."
                          % (e[0], e[1]))
            logging.debug(traceback.format_exc())
            err = Uptrack.resultFromPycurl(config, e)
        except Uptrack.ResultException, e:
            return e.result
        return err

    def showUserStatus(self):
        if self.userStatus is None:
            return None
        try:
            if 'Error' in self.userStatus:
                err = self.userStatus['Error']
                return Uptrack.Result(err['Code'], err['Message'])

            if config.cron and not self.userStatus.get('Cron'):
                return

            if 'Message' in self.userStatus:
                logging.info(self.userStatus['Message'])

            if 'Warning' in self.userStatus:
                logging.error(self.userStatus['Warning'])
        except (TypeError, AttributeError):
            logging.debug("Error parsing user status: ", exc_info=True)
            pass

    def handleStatus(self):
        err = self.downloadUserStatus()
        if err: return err
        try:
            if 'RegenerateCron' in self.userStatus:
                config.regenerateCron()
            if 'Backoff' in self.userStatus:
                config.updateBackoff(self.userStatus['Backoff'])
            if 'RegenerateUUID' in self.userStatus and not config.use_hw_uuid:
                # Must process this last, because it overwrites self.userStatus
                config.olduuid = config.uuid
                config.setUUID(config.newUUID())
                err = self.downloadUserStatus()
                if err: return err
        except TypeError, e:
            # If self.userStatus is not a dict.
            pass

        return self.showUserStatus()


    def downloadPackageList(self):
        logging.debug("Getting package list and signature from "+self.remote_dir)
        err = None
        try:
            c = Uptrack.getCurl()
            for filename in ['packages.yml', 'packages.yml.sig']:
                url = posixpath.join(self.remote_dir, filename)
                filename = os.path.join(self.local_dir, filename)
                try:
                    os.unlink(filename + ".expired")
                except OSError:
                    pass

                s = StringIO.StringIO()
                rcode = Uptrack.download(c, url, filename, stringio=s)
                if rcode in [200, 304]:
                    continue
                elif rcode == HTTP_CODE_EXPIRED:
                    logging.debug("Writing expired data to %s" % (filename + ".expired",))
                    Uptrack.write_file(filename + ".expired", s.getvalue())
                    continue
                elif rcode in [403, 404]:
                    err = Uptrack.Result(Uptrack.ERROR_UNSUPPORTED,
                                         "Cannot find Ksplice Uptrack information "
                                         "for your kernel version\n(%s %s).\n"
                                         "Your kernel is probably not yet supported "
                                         "by Ksplice Uptrack.\n"
                                         "See http://www.ksplice.com/uptrack/supported-kernels "
                                         "for a summary of\nwhat kernels are supported.\n"
                                         "Please contact %s with questions." % \
                                         (config.release, config.version, Uptrack.BUG_EMAIL))
                    logging.debug("Error downloading package list.  Checking key validity.")
                else:
                    err = Uptrack.Result(Uptrack.ERROR_NO_NETWORK,
                                         "Unexpected error connecting to the "
                                         "Ksplice Uptrack server.\n"
                                         "The web server returned "
                                         "HTTP code %03d.  If this error persists,\n"
                                         "please contact %s." % (rcode, Uptrack.BUG_EMAIL))
                    logging.debug("Received unexpected HTTP error code %03d." % rcode)

                return err
        except pycurl.error, e:
            logging.debug("cURL error %d (%s) while downloading package list."
                          % (e[0], e[1]))
            logging.debug(traceback.format_exc())
            err = Uptrack.resultFromPycurl(config, e)
        except IOError:
            err = Uptrack.Result(Uptrack.ERROR_NO_NETWORK,
                                 "Could not save the package list from the "
                                 "Ksplice Uptrack server.\n"
                                 "More details may be available in %s.\n"
                                 "If this error continues, please e-mail %s." %
                                 (LOGFILE, Uptrack.BUG_EMAIL))
            logging.debug(traceback.format_exc())

        return err

    def verifySignature(self, file, sigfile, keyring=None):
        if keyring is None: keyring = KEYRING
        logging.debug("Verifying signature on %s..." % (file,))
        p = subprocess.Popen(['gpgv',
                              '--homedir', UPTRACK_GPG_HOMEDIR,
                              '--keyring', keyring,
                              sigfile,
                              file],
                             stdout = subprocess.PIPE,
                             stderr = subprocess.PIPE)
        stdout, stderr = p.communicate()
        if stdout: logging.debug(stdout)
        if stderr: logging.debug(stderr)
        if p.returncode:
            return False
        return True

    def readPackageList(self):
        if not os.path.exists(self.local_package_list):
            return (Uptrack.Result(Uptrack.ERROR_NO_NETWORK,
                                   "Ksplice Uptrack could not find the package list."), None)

        if not self.verifySignature(self.local_package_list,
                                    self.local_package_list + ".sig"):
            return (Uptrack.Result(1, "Ksplice Uptrack could not verify"
                                   " the package list signature."),
                    None)

        logging.debug("Trying to read package list at %s" % self.local_package_list)
        try:
            pl = Uptrack.yaml_load(open(self.local_package_list))
            if os.path.isfile(self.local_package_list + ".expired"):
                if not self.verifySignature(
                    self.local_package_list + ".expired",
                    self.local_package_list + ".sig.expired"):
                    return (Uptrack.Result(1, "Ksplice Uptrack could not verify"
                                           " the package list signature."),
                            None)
                expired = Uptrack.yaml_load(open(
                        self.local_package_list + ".expired", 'r'))
                pl['Expired'] = expired
        except (IOError, yaml.YAMLError):
            logging.debug("Error reading the package list", exc_info=1)
            err = Uptrack.Result()
            if not config.init:
                err.code = Uptrack.ERROR_NO_NETWORK
            err.message = "Cannot load the package list.\n"
            # If config.allow_net is true, we already downloaded the
            # package list, so barring possible weird edge cases, this
            # is almost certainly a bug.

            # If we don't have network, instruct the user to try again
            # with network, in the hopes that re-downloading the
            # package list will fix things.
            if not config.allow_net:
                err.message += "Please re-run the Ksplice Uptrack client with a network connection available."
            else:
                err.message += "Please report a bug to %s" % (Uptrack.BUG_EMAIL,)
            return err, None

        client = pl['Client']

        version = pl['Protocol version']
        # Check versions
        if self.protocolVersion != version:
            local.new_client = True
            return (Uptrack.Result(1,
                      "Protocol version mismatch: %s != %s\n"
                      "Please use your package manager to update this client."
                      % (self.protocolVersion, version)),
                    None)

        needVersion = client.get('Version to Parse', '0')
        if Uptrack.compareversions(self.clientVersion, needVersion) < 0:
            local.new_client = True
            return (Uptrack.Result(Uptrack.ERROR_TOO_OLD_PARSE,
                      "Ksplice Uptrack client too old: %s, require %s\n"
                      "Please use your package manager to update this client."
                      % (self.clientVersion, needVersion)),
                    None)

        # Sanity check

        kernel = pl['Kernel']
        if config.release != kernel['Release']:
            return (Uptrack.Result(1, "Kernel release mismatch: %s != %s"
                                      % (config.release, kernel['Release'])), None)
        if config.version != kernel['Version']:
            return (Uptrack.Result(1, "Kernel version mismatch: %s != %s"
                                      % (config.version, kernel['Version'])), None)
        if config.arch != kernel['Architecture']:
            return (Uptrack.Result(1, "Wrong architecture: %s != %s"
                                      % (config.arch, kernel['Architecture'])), None)

        if 'Error' in pl:
            e = pl['Error']
            return Uptrack.Result(e['Code'], e['Message']), None

        return None, pl

    def parsePackageList(self):
        err, pl = self.readPackageList()
        if pl is None:
            return err
        packages = {}
        for i, item in enumerate(pl['Updates']):
            u = makeUpdate(item, self.local_dir, self.remote_dir, i)
            packages[u.id] = u
        self.updates = packages

        version = pl['Client'].get('Version to Install', '0')
        if Uptrack.compareversions(self.clientVersion, version) < 0:
            local.new_client = True
            return Uptrack.Result(Uptrack.ERROR_TOO_OLD_INSTALL,
                      "Ksplice Uptrack client too old: %s, require %s\n"
                      "Please use your package manager to update this client."
                      % (self.clientVersion, version))

        version = pl['Client']['Ksplice Tools API version']

        if self.kspliceToolsApiVersion == '-1':
            return Uptrack.Result(1,
                      "Error: %s: No such file or directory" % (API_VERSION_FILE,))
        if Uptrack.compareversions(self.kspliceToolsApiVersion,
                                   version) < 0:
            local.new_client = True
            return Uptrack.Result(1,
                      "Ksplice Uptrack client too old: tools API version %s < %s\n"
                      "Please use your package manager to update this client."
                      % (self.kspliceToolsApiVersion, version))
        elif self.kspliceToolsApiVersion != version:
            return Uptrack.Result(1,
                      "Ksplice Uptrack client too new: tools API version %s > %s\n"
                      "Please report this problem to %s."
                      % (self.kspliceToolsApiVersion, version,
                         Uptrack.BUG_EMAIL))

        global alert, desupported, tray_icon_error
        alert = pl.get('Alert')
        desupported = pl.get('Desupported')
        tray_icon_error = pl.get('TrayIconError')
        if alert and (desupported or not config.cron):
            logging.warning(alert)

        expired = pl.get('Expired')
        if expired:
            self.expired = True
            if 'Message' in expired:
                logging.warning(expired['Message'])

        return err

    def downloadPackages(self):
        logging.debug("Downloading packages.")
        updates = self.updates.values()
        updates.sort(Uptrack.cmp_order)
        for u in updates:
            if u.isValidFile():
                logging.debug("Already have %s, skipping" % u)
                continue
            logging.debug("Downloading %s" % u)
            try:
                Uptrack.mkdirp(os.path.dirname(u.local_path))
                rcode = Uptrack.download(Uptrack.getCurl(),
                                         u.remote_path,
                                         u.local_path,
                                         ifmodified=False)
                if rcode != 200:
                    return Uptrack.Result(1,
                                         "Unexpected error downloading update %s.\n"
                                         "The web server returned HTTP code %03d.\n"
                                         "If this error persists, please contact %s." %
                                          (u.id, rcode, Uptrack.BUG_EMAIL))

            except (IOError, pycurl.error):
                err = Uptrack.Result()
                err.code = 1
                err.message = ("Couldn't download update '%s'.\n"
                               "Please check your network connection and try "
                               "again.\nIf this error continues, e-mail %s." %
                               (u, Uptrack.BUG_EMAIL))
                logging.debug("Error downloading update %s." % u.filename)
                logging.debug("Remote: %s" % u.remote_path)
                logging.debug("Local: %s" % u.local_path)
                logging.debug(traceback.format_exc())
                return err
            logging.debug("Unpacking %s" % u)
            res = u.unpack()
            if res.code:
                return res

    def downloadAll(self):
        res = repo.downloadPackageList()
        if res:
            return res
        res = repo.parsePackageList()
        if res:
            return res
        return repo.downloadPackages()

    def getAllUpdates(self):
        if self.updates is None:
            raise "BUG: Package list has not yet been read."
        return set(self.updates.values())

    def idToUpdate(self, id):
        """
        Turns ID into Update, or returns
        None if we don't know about it
        """
        if self.updates:
            return self.updates.get(id, None)

class AlarmSignaled(Exception):
    pass

def onAlarm(sig, frame):
    raise AlarmSignaled

def getLock():
    lockdir = os.path.dirname(config.lockfile)
    if not os.path.isdir(lockdir):
        try:
            os.makedirs(lockdir)
        except IOError:
            return False
    old_handler = None
    try:
        try:
            old_handler = signal.signal(signal.SIGALRM, onAlarm)
            f = open(config.lockfile, 'w')
            signal.alarm(LOCK_TIMEOUT)
            fcntl.flock(f, fcntl.LOCK_EX)
        except (IOError, AlarmSignaled):
            return False
    finally:
        signal.alarm(0)
        if old_handler is not None:
            signal.signal(signal.SIGALRM, old_handler)

    return f

def releaseLock():
    """
    The fd is closed when the variable goes out
    of scope or the process is exited, so this shouldn't
    really be necessary, but is here in case you want
    to explicitly release the lock
    """
    fcntl.flock(lock, fcntl.LOCK_UN)
    lock.close()

class UptrackClientConfig(Uptrack.UptrackConfig):
    def __init__(self, program, args):
        super(UptrackClientConfig, self).__init__()
        command = extractCommand(os.path.basename(program))
        if command in [INSTALL, REMOVE]:
            usage = "usage: %prog [options] <id>..."
        elif command == SHOW:
            usage = "usage: %prog [options] [<id>...]"
        elif command == UPGRADE:
            usage = "usage: %prog [options]"
        parser = OptionParser(usage=usage)
        parser.add_option("-q", "--quiet",
                          action="store_const",
                          const=-1,
                          dest="verbose",
                          help="don't print status messages")
        parser.add_option("-v", "--verbose",
                          action="count",
                          dest="verbose",
                          help="provide more detail about what this program is doing",
                          default=0)
        parser.add_option("-y",
                          action="store_true",
                          dest="answer_yes",
                          default=False,
                          help="answer 'yes' to all user prompts")
        parser.add_option("-n",
                          action="store_true",
                          dest="answer_no",
                          default=False,
                          help="answer 'no' to all user prompts")
        parser.add_option("--wait", type="float", dest="wait", default=0,
                          help="time to wait between applying updates")
        parser.add_option("--no-network",
                          action="store_false", dest="allow_net", default=True,
                          help=SUPPRESS_HELP)
        parser.add_option("--all",
                          action="store_true", dest="all", default=False,
                          help="take action for all updates")
        parser.add_option("--cron",
                          action="store_true", dest="cron", default=False,
                          help=SUPPRESS_HELP)
        parser.add_option("--init",
                          action="store_const", dest="init", default=None,
                          const='early', help=SUPPRESS_HELP)
        parser.add_option("--late-init",
                          action="store_const", dest="init", const="late",
                          help=SUPPRESS_HELP)
        parser.add_option("--shutdown",
                          action="store_const", dest="init", const="shutdown",
                          help=SUPPRESS_HELP)
        parser.add_option("--check-init",
                          action="store_true", dest="check_init", default=False,
                          help=SUPPRESS_HELP)
        parser.add_option("--count",
                          action="store_true", dest="count", default=False,
                          help=SUPPRESS_HELP)
        parser.add_option("--uninstall",
                          action="store_true", dest="uninstall", default=False,
                          help=SUPPRESS_HELP)
        parser.add_option("--available",
                          action="store_true", dest="available", default=False,
                          help=SUPPRESS_HELP)
        parser.add_option("-V", "--version",
                          action="store_true",
                          dest="show_version",
                          help="print the version information and exit",
                          default=False)
        parser.add_option('--i-accept-the-terms-of-service',
                          action='store_true', dest='accept_tos', default=False,
                          help=SUPPRESS_HELP)

        (options, args) = parser.parse_args(args)
        self.options = options
        self.args = args

        self.setVerbosity()
        self.setTask()

    def setVerbosity(self):
        self.verbose = self.options.verbose

    def setTask(self):
        self.disabled = os.path.isfile("/etc/uptrack/disable")
        self.disablecmd = 'nouptrack' in Uptrack.read_file("/proc/cmdline")

        self.answer_yes = self.options.answer_yes
        self.answer_no = self.options.answer_no
        if self.answer_yes and self.answer_no:
            self.answer_yes = self.answer_no = False
        self.allow_net = self.options.allow_net
        self.all = self.options.all
        self.available = self.options.available

        ## Unattended operation modes
        self.cron = False
        self.uninstall = False
        self.init = False

        if self.options.uninstall:
          self.uninstall = True
          self.all = True
          self.answer_yes = True

        self.cron_autoinstall = Uptrack.getConfigBooleanOrDie(
            self.config, 'Settings', 'autoinstall', False)

        self.install_on_reboot = Uptrack.getConfigBooleanOrDie(
            self.config, 'Settings', 'install_on_reboot', True)
        self.upgrade_on_reboot = Uptrack.getConfigBooleanOrDie(
            self.config, 'Settings', 'upgrade_on_reboot', False)

        if self.options.cron:
            self.cron = True
            self.answer_yes = self.cron_autoinstall
            self.answer_no = not self.cron_autoinstall
            self.verbose = -2

        if self.options.init:
            self.init = self.options.init
            self.verbose -= 1
            if self.init == 'early':
                self.answer_yes = True
                self.answer_no = False
                self.allow_net = False
            elif self.init == 'late':
                self.answer_yes = self.upgrade_on_reboot
                self.answer_no = not self.answer_yes
            elif self.init == 'shutdown':
                self.answer_yes = False
                self.answer_no = True

        self.wait = self.options.wait
        self.accept_tos = self.options.accept_tos

    def checkDeprecatedOptions(self):
        if self.cron:
            return

        show_cron_output_warning = False
        for suffix in ('install', 'available', 'error'):
            option = 'cron_output_' + suffix
            if Uptrack.getConfigBooleanOrDie(self.config, 'Settings', option, False):
                show_cron_output_warning = True

        if show_cron_output_warning:
            logging.warning("Warning: The cron output configuration options have been removed.")
            logging.warning("Please visit <http://www.ksplice.com/uptrack/notification-options>")
            logging.warning("for more information.")

class PermissionedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    A subclass of logging.handlers.RotatingFileHandler which sets user,
    group, and permissions.
    """
    def __init__(self, filename, **kwargs):
        self._ks_filename = filename

        try:
          self._ks_uid = pwd.getpwnam(LOGUSER )[2]
          self._ks_gid = grp.getgrnam(LOGGROUP)[2]
        except KeyError:
          self._ks_uid = None
          self._ks_gid = None
        self._ks_umask = LOGMODE ^ 0777

        old = os.umask(self._ks_umask)
        logging.handlers.RotatingFileHandler.__init__(self, filename, **kwargs)
        os.umask(old)

        self._ksplice_chown()

    def _ksplice_chown(self):
        # not security critical; by default the file will be root:root
        if self._ks_uid is None:
            return

        try:
            os.chown(self._ks_filename, self._ks_uid, self._ks_gid)
        except OSError:
            pass

    def emit(self, *args, **kwargs):
        old = os.umask(self._ks_umask)
        logging.handlers.RotatingFileHandler.emit(self, *args, **kwargs)
        os.umask(old)

    def doRollover(self, *args, **kwargs):
        logging.handlers.RotatingFileHandler.doRollover(self, *args, **kwargs)
        self._ksplice_chown()

class Logger(object):
    def __init__(self):
        my_logger = logging.getLogger('')
        my_logger.setLevel(logging.DEBUG)
        consoleLevel = logging.INFO

        logging.raiseExceptions = False
        self.console_logger = logging.StreamHandler(sys.stdout)
        self.console_logger.setLevel(consoleLevel)
        formatter = logging.Formatter('%(message)s')
        self.console_logger.setFormatter(formatter)

        fformat = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        filelogger = PermissionedRotatingFileHandler(LOGFILE,
                                                     maxBytes=2.5*1024*1024,
                                                     backupCount=2)
        filelogger.setLevel(logging.DEBUG)
        filelogger.setFormatter(fformat)

        self.debug_log = StringIO.StringIO()
        self.debug_logger = logging.StreamHandler(self.debug_log)
        self.debug_logger.setLevel(logging.DEBUG)
        self.debug_logger.setFormatter(fformat)

        logging.getLogger('').addHandler(filelogger)
        logging.getLogger('').addHandler(self.console_logger)
        logging.getLogger('').addHandler(self.debug_logger)

    def getDebugLog(self):
        try:
            logging.getLogger('').removeHandler(self.debug_logger)
            return self.debug_log.getvalue()
        except:
            return None

    def configure(self, config):
        consoleLevel = logging.INFO
        if config.verbose < -1:
            consoleLevel = logging.CRITICAL
        elif config.verbose < 0:
            consoleLevel = logging.ERROR
        elif config.verbose > 0:
            consoleLevel = logging.DEBUG

        self.console_logger.setLevel(consoleLevel)

def confirm(msg):
    if config.answer_yes:
        return True
    if config.answer_no:
        return False

    logging.info("")
    take_action = 'n'
    try:
        take_action = raw_input("%s [y/N]? " % msg)
    except (KeyboardInterrupt, EOFError):
        print
        pass
    if len(take_action) < 1 or take_action[0].lower() != 'y':
        return False
    return True

def doRemove(repo, local, wish_to_remove):
    if config.all:
        wish_to_remove = [u.id for u in local.getInstalledUpdates()]
    return planAndDoActions(repo, local, [(REMOVE,x) for x in wish_to_remove])

def doUpgrade(repo, local):
    # Shortcut the answer_no case to avoid an additional round-trip
    if config.answer_no:
        try:
            (_, new_upgrade, new_init, new_remove) = planActions(repo, local, [])
        except Uptrack.ResultException, e:
            return e.result
        if len(new_upgrade) == 0:
            if not config.cron:
                printEffective()
                logging.info("Nothing to be done.")
        else:
            printEffective()
            displayAndConfirm(new_upgrade)
        local.writeOutStatus(None, new_upgrade, new_init, new_remove)
        return Uptrack.Result()

    res = planAndDoActions(repo, local, [(INSTALL, 'head')])
    if not res.code:
        if not config.cron:
            logging.info("Your kernel is fully up to date.")
            printEffective()
    return res

def doInstall(repo, local, wish_to_install):
    if config.all:
        return doUpgrade(repo, local)
    else:
        return planAndDoActions(repo, local, [(INSTALL,x) for x in wish_to_install])

def printEffective(blank_line=False):
    kernel = local.getEffective()
    if kernel is not None:
        if blank_line:
            logging.info("")
        logging.info("Effective kernel version is %s"
                     % (kernel['PackageVersion'],))

def planActions(repo, local, actions):
    """:: Repo -> Local -> [Action] -> IO (Plan, Plan, Plan, Plan)
    data Action = Install Kid | Remove Kid
    -- Implemented as (INSTALL|REMOVE, Kid)
    -- Installing the pseudo-kid "head" means "upgrade fully".
    type Plan = [(INSTALL|REMOVE,Update)]

    Given a set of requested actions, return a set of four plans
    appropriate to carry out those actions and then update our state.

    The four returned plans are, in order:
    *) A plan that includes the requested actions
    *) A new upgrade plan, assuming we perform the first plan succesfully.
    *) A new init-time plan, assuming we perform the first plan succesfully.
    *) A new remove-all plan, assuming we perform the first plan succesfully
       (this is used if we are trying to remove all updates and don't have
        network connectivity).

    """

    logging.debug("Constructing plans for the actions: " + str(actions))

    installed = local.getInstalledUpdates()

    new_actions = []
    for act in actions:
        command, id = act
        u = repo.idToUpdate(id)
        if u is None and id != "head":
            logging.warning("Unknown update %s, skipping." % (id,))
        elif command == INSTALL and u in installed:
            logging.warning("Update %s is already installed, skipping." % (id,));
        elif command == REMOVE and u not in installed:
            logging.warning("Update %s is not installed, skipping." % (id,));
        else:
            new_actions.append(act)

    actions = new_actions

    installed_ids = [u.id for u in installed]
    locked_ids    = [u.id for u in installed if u.isLocked()]
    solver = UptrackDepSolver.UptrackDepSolver(local, installed_ids, locked_ids)

    response = solver.getPlans(actions)
    plan, upgrade, init, remove = [response[k] for k in
      ('Steps', 'Upgrade Plan', 'Init Plan', 'Remove Plan')]
    if 'EffectiveKernel' in response:
        local.setEffective(response['EffectiveKernel'])
    if False in [act['ID'] in repo.updates for act in plan + upgrade + init + remove]:
        # Make sure packages.yml and associated state are up to date
        res = repo.downloadAll()
        if res and res.code != 0:
            raise Uptrack.ResultException(res.code, res.message)

        for act in plan + upgrade + init + remove:
            if act['ID'] not in repo.updates:
                raise Uptrack.ResultException(Uptrack.ERROR_INTERNAL_SERVER_ERROR,
                                              textwrap.fill(
"""Error: Server asked that we %s unknown update %s.
Please report this issue to support@ksplice.com.
""" % (act['Command'].lower(), id)))

    local.unpackPlan(plan)
    local.unpackPlan(upgrade)
    local.unpackPlan(init)
    local.unpackPlan(remove)

    return (plan, upgrade, init, remove)

def planAndDoActions(repo, local, actions):
    """:: Repo -> Local -> [Action] -> Uptrack.Result

    Construct a plan to perform the requested actions, and then carry
    out said plan. In addition, write new upgrade, init-time, and
    remove plans appropriate for the new state.
    """

    try:
        (plan, new_update, new_init, new_remove) = planActions(repo, local, actions)
    except Uptrack.ResultException, e:
        return e.result

    if len(plan) == 0:
        if not config.cron:
            logging.info("Nothing to be done.")
    elif not displayAndConfirm(plan):
        return Uptrack.Result(Uptrack.ERROR_USER_NO_CONFIRM, "Aborting.")

    res = doActions(plan, local)

    if res.code:
        return res

    # We succeeded. Write out the new update, init-time, and remove
    # plans the server gave us. Don't write out our result, since
    # quit() will do that for us.
    local.writeOutStatus(None, new_update, new_init, new_remove)

    return res

def doInitClean(local):
    dir = "/var/run/ksplice"
    file = "/var/run/uptrack"
    if os.path.isdir(dir):
        logging.debug("Cleaning up stale state in %s and %s" % (dir, file))
        try:
            shutil.rmtree(dir)
        except Exception, e:
            if isinstance(e, OSError) and e.errno == errno.ENOENT:
                pass
            else:
                logging.error("An error occurred while removing %s" % dir)
                logging.debug(traceback.format_exc())
    if os.path.exists(file):
        try:
            os.unlink(file)
        except e:
            if isinstance(e, OSError) and e.errno == errno.ENOENT:
                pass
            logging.error("An error occurred while removing %s" % file)
            logging.debug(traceback.format_exc())

def doInit(repo, local):
    """
    Execute the init-time plan previously written to disk
    """
    inst = local.getInstalledUpdates()
    if len(inst) != 0:
        msg = "\nError: Uptrack init script started, but some updates are already installed!\n\n" + \
              textwrap.fill(
               "This is most likely because you manually ran '/etc/init.d/uptrack start'. " +
               "You never need to run the Uptrack init script manually: There is no Uptrack " +
               "daemon to start.  This init script only exists to reinstall your updates " +
               "during the boot process.  Please contact %s if you have any questions." % Uptrack.BUG_EMAIL)
        return Uptrack.Result(1, msg)

    doInitClean(local)

    if not config.install_on_reboot:
        logging.debug("init-time installation is disabled.")
        return Uptrack.Result()

    plan = []
    try:
        logging.debug("Reading init-time plan...")
        plan = local.readInitPlan()
        logging.debug("Installing updates according to the init-time plan:")
        logging.debug(plan)
    except (IOError, yaml.YAMLError):
        logging.debug("Error reading init-time plan; doing nothing")
        logging.debug(traceback.format_exc())
        return Uptrack.Result(1, "Error reading init-time plan")

    return doActions(plan, local)

def doOfflineRemoveAll(repo, local):
    """
    Execute the remove_plan previously written to disk
    """
    res = Uptrack.Result()
    inst = local.getInstalledUpdates()

    plan = []
    try:
        logging.debug("Reading remove plan...")
        plan = local.readRemovePlan()
    except (IOError, yaml.YAMLError):
        logging.debug("Error reading remove-all plan; doing nothing")
        logging.debug(traceback.format_exc())
        res.code = 1
        res.message = "Error reading remove-all plan"
        return res

    if len(plan) == 0:
        if not config.cron:
            logging.info("Nothing to be done.")
    elif not displayAndConfirm(plan):
        logging.info("Aborting.")
        return Uptrack.Result()

    res = doActions(plan, local)
    if res.code: return res

    # We succeeded, so write out empty init and remove plans (since
    # we've successfully removed all of the updates, it's reasonable
    # to do nothing at boot-time).

    # We could potentially reverse the remove plan we just executed
    # and write it out as an upgrade plan, but since we will refuse to
    # execute it without network, anyways, we just write out an empty
    # one, and an error message informing the user to try again when
    # network is available.

    if not config.uninstall:
      res = Uptrack.Result(Uptrack.ERROR_NO_NETWORK,
                           "New updates %s available. Please re-run "
                           "Uptrack with a network connection available\n"
                           "to view and install them" %
                           ({True:'are',False:'may be'}[len(plan) > 0],))

    # Don't write out a result, since quit() will do that for us.
    local.writeOutStatus(None, [], [], [])
    return res

def displayAndConfirm(actions):
    if not config.cron:
        logging.info("The following steps will be taken:")
        for act in actions:
            logging.info("%s %s" % (act['Command'], act['Update']))
    return confirm("Go ahead")

def doActions(actions, local):
    res = Uptrack.Result()
    inst = local.getInstalledUpdates()
    count = len(actions)
    depmod_needed = os.path.exists(DEPMOD_NEEDED_FILE)
    for i in range(count):
        command, u = [actions[i][k] for k in ('Command', 'Update')]
        new_effective = actions[i].get('EffectiveKernel')
        commandwords = {INSTALL: 'Installing', REMOVE: 'Removing'}
        logging.info("%s %s" % (commandwords[command], u))
        config.notify.WorkingOnUpdate(command.upper(), i, count, u.id, u.name)
        if command == INSTALL:
            if u in inst:
                logging.warning("...%s is already installed, so skipping" % u.id)
                continue
            else:
                r = u.applyUpdate()
        elif command == REMOVE:
            if u not in inst:
                logging.warning("...%s is not installed, so not removing" % u.id)
                continue
            else:
                r = u.undoUpdate()
        else:
            pass

        if r.code:
            logging.warning("Error processing %s" % u.filename)
            res.failed.append(r)
            res.code = r.code
            if config.debug_to_server:
                res.debug = r.debug
            break
        else:
            res.succeeded.append(r)
            if command == INSTALL:
                inst.add(u)
            elif command == REMOVE:
                inst.remove(u)
            depmod_needed = depmod_needed or r.depmod_needed
            if new_effective is not None:
                local.setEffective(new_effective)

        if config.wait:
            logging.debug("Sleeping %s seconds between updates, as requested" % config.wait)
            time.sleep(config.wait)

    if depmod_needed:
        try:
            os.unlink(DEPMOD_NEEDED_FILE)
        except:
            pass
        config.notify.WorkingOnUpdate('DEPMOD', count, count, '', '')
        ## modprobe.ksplice uses the presence of /var/run/uptrack to decide
        ## whether it should the modules.dep file managed by Ksplice
        ## or the normal modules.dep file.
        ## /var/run/uptrack is automatically removed after every reboot
        if not os.path.isfile('/var/run/uptrack'):
            Uptrack.write_file('/var/run/uptrack', "uptrack\n")

        code = os.system("/sbin/ksplice-depmod -a")
        if code and not res.code:
            try:
                Uptrack.write_file(DEPMOD_NEEDED_FILE, "True")
            except:
                pass
            return Uptrack.Result(1, "Error running ksplice-depmod.")

    return res

def doShowUpgradePlan(repo, local):
    try:
        plan = local.readUpgradePlan()
    except IOError,e:
        logging.error("Unable to read the list of available updates.\n"
                      "Please run 'uptrack-upgrade -n' to update "
                      "the list of available updates.")
        sys.exit(1)

    logging.info("Available updates:")
    if plan:
        for act in plan:
            if act['Command'] == 'Install':
                logging.info(act['Update'])
    else:
        logging.info(None)

def doShow(repo, local, wish_to_show):
    """
    show has two modes of operation:
    
    When run without arguments, it lists the current status (i.e. what
    is installed). When arguments are passed to it, it shows you the
    detailed information for those updates.
    """
    all_updates = repo.getAllUpdates()
    inst = local.getInstalledUpdates()

    if config.options.count:
        logging.info(len(inst))
        sys.exit(0)

    can_show = set()
    for id in wish_to_show:
        u = repo.idToUpdate(id)
        if u is None:
            logging.warning("Don't know about update %s; skipping." % id)
            continue
        can_show.add(u)


    if len(wish_to_show) == 0:
        if config.available or config.all:
            doShowUpgradePlan(repo, local)

        if (not config.available) or config.all:
            logging.info("Installed updates:")
            if not len(inst):
                logging.info("None")
            else:
                inst_sorted = list(inst)
                inst_sorted.sort(Uptrack.cmp_order)

                for u in inst_sorted:
                    logging.info(u)

        printEffective(blank_line=True)
    else:
        # Python 2.3 doesn't have sorted() or sort(key = ...)
        can_show_sorted = list(can_show)
        can_show_sorted.sort(Uptrack.cmp_order)
        for u in can_show_sorted:
            if u in inst:
                logging.info("Update %s is installed on your system.  Detailed description:\n" % u.id)
            else:
                logging.info("Update %s is NOT installed on your system.  Detailed description:\n" % u.id)
            p = u.getDetails()
            if p == '':
                p = "Unable to retrieve detailed description of update %s." % u.id
            else:
                p = p.strip() + "\n"
            logging.info(p)
    return None

if have_dbus:
    class DbusNotifications(dbus.service.Object):
        def __init__(self, object_path):
            dbus.service.Object.__init__(self, dbus.SystemBus(), object_path)

        def ClientStartStop(self, action):
            logging.debug("dbus: Action: %s" % (action))
        ClientStartStop = dbus.service.signal(dbus_interface='com.ksplice.uptrack.Client',
                                              signature='s')(ClientStartStop)

        def WorkingOnUpdate(self, action, num, total, id, desc):
            logging.debug("dbus: Working on update: %s %i %i %s %s" %
                          (action, num, total, id, desc))
        WorkingOnUpdate = dbus.service.signal(dbus_interface='com.ksplice.uptrack.Client',
                                              signature='siiss')(WorkingOnUpdate)

class NonDbusNotifications(object):
    def __init__(self, object_path): pass
    def ClientStartStop(self, action):
        pass
    def WorkingOnUpdate(self, action, num, total, id, desc):
        pass

def isOk(res):
    if res: quit(res)

def quit(result):
    """:: Uptrack.Result -> IO ()

    Exit the program, performing appropriate reporting and cleanup
    before we do so. In particular, we must write the current status
    and result to disk (for the UI) and back to the server.

    In addition, we need to make sure we have written out an upgrade
    plan (for the GUI to display), an init-time plan (for next boot),
    and a remove plan (for if we try to remove all updates without
    network).

    If we are exiting successfully, the previous code paths have
    written out new plans if needed. If we're exiting with failure,
    however, we don't know what state we're in, so compute new plans
    to be safe.
    """
    if result:
        if alert: result.alert = alert
        if desupported: result.desupported = desupported
        if tray_icon_error: result.tray_icon_error = tray_icon_error

    if result and result.code == Uptrack.ERROR_USER_NO_CONFIRM:
        logging.debug("User did not confirm actions. Not writing new plans.")
        local.writeOutStatus(result, None, None, None)
    elif config.allow_net and result and result.code and repo.updates and \
            result.code not in (Uptrack.ERROR_UNSUPPORTED,
                                Uptrack.ERROR_NO_NETWORK,
                                Uptrack.ERROR_INVALID_KEY,
                                Uptrack.ERROR_MACHINE_NOT_ACTIVATED,
                                Uptrack.ERROR_EXPIRED,
                                Uptrack.ERROR_SYS_NOT_MOUNTED,
                                Uptrack.ERROR_MISSING_KEY):
        try:
            logging.debug("Determining new upgrade/init-time/remove plans.")
            (_, upgrade, init, remove) = planActions(repo, local, [])
            local.writeOutStatus(result, upgrade, init, remove)
        except Exception:
            if result.code == Uptrack.ERROR_INTERNAL_SERVER_ERROR:
                report = logging.debug
            else:
                report = logging.error
            report("Error making upgrade/init-time/remove plans")
            logging.debug(traceback.format_exc())
            report("")

            if result and result.code != 0:
                local.writeOutStatus(result, None, None, None)
            else:
                # Something did go wrong. However, if we just used `result`,
                # the GUI wouldn't notice because the result code is zero.
                internal_error = Uptrack.Result()
                internal_error.code = 1
                internal_error.message = ("Internal error while writing Uptrack"
                    "status files.\nSee %s for more details.") % LOGFILE
                local.writeOutStatus(internal_error, None, None, None)
    elif result and result.code:
        logging.debug("Failed, but running without network. Not writing new plans.")
        local.writeOutStatus(result, None, None, None)
    else:
        logging.debug("Exiting with success. Not writing new plans.")
        local.writeOutStatus(result, None, None, None)

    if result and result.message:
        if result.code != 0 and result.code != Uptrack.ERROR_USER_NO_CONFIRM:
            if config.cron and result.code in (Uptrack.ERROR_NO_NETWORK,
                                               Uptrack.ERROR_INTERNAL_SERVER_ERROR,
                                               Uptrack.ERROR_EXPIRED,
                                               Uptrack.ERROR_MACHINE_NOT_ACTIVATED):
                # Don't send cron email about these transient failures; just log them.
                logging.debug(result.message)
            else:
                logging.error(result.message)
        else:
            logging.info(result.message)
    config.notify.ClientStartStop('STOP')
    code = 0
    if result: code = result.code
    sys.exit(code)

def prettyResult(act):
  msg = None
  why = act.abort_code
  if why:
    if why == 'code_busy' and len(act.stack_check_processes) == 1 and \
       act.stack_check_processes[0][0] == 'krfcommd':
      msg = "Ksplice was unable to " + act.command.lower() + \
          " the update because the rfcomm module (used for bluetooth)" + \
          " is erroneously triggering a conservative Ksplice safety check. " + \
          " If you are not using bluetooth on this system, you can install this" + \
          " update by first unloading the rfcomm module using \"rmmod rfcomm\" and trying" + \
          " again.  Please contact %s if you have any questions." % Uptrack.BUG_EMAIL
      msg = "\n" + textwrap.fill(msg)
    elif why == 'code_busy':
      msg = "Ksplice was unable to " + act.command.lower() + \
          " the update because one or more programs are constantly" + \
          " using the kernel functions patched by this update.  You" + \
          " should be able to install this update by trying again.  If" + \
          " trying again does not work, please report this problem to" + \
          " <%s>. " % Uptrack.BUG_EMAIL + \
          " Even if trying again does not work, closing the following" + \
          " programs should make it possible to install this update:"
      msg = "\n" + textwrap.fill(msg) + "\n\n"
      for proc in act.stack_check_processes:
        p, pid = proc[0:2]
        msg += "  - %s (pid %s)\n" % (p, pid)
    elif why == 'out_of_memory':
      msg = "Ksplice failed to " + act.command.lower() + \
          " this update because your kernel is out of memory.  Ksplice's memory" + \
          " consumption is minimal, so this is likely caused by some other problem" + \
          " on your system"
      msg = "\n" + textwrap.fill(msg)
    elif why == 'cold_update_loaded':
      msg = "Ksplice was unable to remove the update because modules" + \
          " that Uptrack patched off-line are currently loaded.  In order" + \
          " to remove this update, you will need to first unload the" + \
          " following kernel modules:"
      msg = "\n" + textwrap.fill(msg)
      msg += "\n\n"
      msg += "\n".join([" - %s" % (m,) for m in act.locked_modules])
    elif why in ['no_match', 'failed_to_find']:
      if Uptrack.inVirtualBox():
        msg = "\n" + textwrap.fill(
            "Ksplice was unable to " + act.command.lower() +
            " the update because it could not match the code to be"
            " patched in your running kernel.  This could be caused by"
            " running Ksplice inside VirtualBox without the VT-x/AMD-V"
            " setting enabled.")
        msg += (
            "\n"
            "For more information, see http://www.ksplice.com/uptrack/help/virtualbox"
            "\n\n")
        msg += textwrap.fill(
            "If you are not running VirtualBox, or enabling VT-x/AMD-V"
            " does not solve the problem, please report this bug to "
            + Uptrack.BUG_EMAIL + ".")
      elif len(act.nomatch_modules) > 0:
        msg = "\n" + textwrap.fill(
            "Ksplice was unable to install this update because the code in your running" +
            " kernel does not match the expected version.") + "\n"
        if os.path.exists('/etc/debian_version'):
          # This only happens on Debian / Ubuntu, due to their policy of not always
          # updating 'uname -r'.
          msg += "\n" + textwrap.fill(
              "You may have upgraded your on-disk kernel package and subsequently loaded"
              " one of the updated modules.  You may also be running a backported or"
              " custom-compiled kernel module.  The non-matching modules are:") + "\n\n"
        else:
          msg += "\n" + textwrap.fill(
              "You may be running a backported or custom-compiled version of" +
              " one or more of the following kernel modules that were provided by"
              " your Linux vendor:") + "\n\n"
        for module in act.nomatch_modules:
          msg += "  - %s\n" % module
        msg += "\n" + textwrap.fill(
            "If you are not intentionally using a different version of these modules," +
            " you should be able to install this update by running the following"
            " commands as root:") + "\n"
        for module in act.nomatch_modules:
          msg += "\n" + "rmmod " + module
        msg += "\n\n" + textwrap.fill("and then trying again. " +
          " If you are unable to resolve this issue, please contact" +
          " <%s> for assistance. " % Uptrack.BUG_EMAIL)
      else:
        msg = "\n" + textwrap.fill(
            "Ksplice was unable to install this update because your running" +
            " kernel has been modified from the version provided by your vendor.")
        msg += (
            "\n"
            "Please contact %s for help resolving this issue." % (Uptrack.BUG_EMAIL,))
    elif why == 'module_busy' and act.command == REMOVE and act.usedby_modules:
      msg = "\n" + textwrap.fill("Ksplice was unable to remove" +
          " the update because it is in use by one or more kernel modules" +
          " that have been loaded since the update was applied.  In order" +
          " to remove this update, you will need to first unload the" +
          " following kernel modules:"
          )
      msg += "\n\n"
      msg += "\n".join([" - %s" % (m,) for m in act.usedby_modules])
      msg += "\n\n" + textwrap.fill(
          "You can unload a module by running \"rmmod <module name>\" as root." +
          " If you are unable to resolve this issue, please contact" +
          " <%s> for assistance. " % Uptrack.BUG_EMAIL)
  if not msg:
    msg = "Ksplice was unable to " + act.command.lower() + " this update" + \
        " due to an unexpected internal error."
    msg = "\n" + textwrap.fill(msg)

    msg += "\n\n"

    msg += "Please report this bug to the Uptrack developers at <%s>.\n" % (Uptrack.BUG_EMAIL,)
    msg += "Uptrack log file: %s" % (LOGFILE,)

  return msg

def initializeDBus():
    if have_dbus and not config.init: # No dbus at init!
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        notify = DbusNotifications('/com/ksplice/uptrack/UptrackUI')
    else:
        logging.debug("D-Bus not present, will not notify uptrack-manager.")
        notify = NonDbusNotifications('/com/ksplice/uptrack/UptrackUI')
    config.notify = notify

def desync():
    logging.debug("Invoked by the cron job.")

    counterfile = config.localroot+'/backoff-counter'
    try:
        backoff = float(Uptrack.read_file(config.localroot+'/backoff'))
        backoff_counter = float(Uptrack.read_file(counterfile))
    except (IOError, ValueError):
        backoff = 1
        backoff_counter = 0
    backoff_counter += 1
    if backoff_counter < backoff:
        logging.debug("Counter is %s/%s, waiting for next time.",
                     backoff_counter, backoff)
        Uptrack.write_file(counterfile, str(backoff_counter)+'\n')
        sys.exit(0)
    logging.debug("Counter is %s/%s, proceeding.", backoff_counter, backoff)
    backoff_counter -= backoff
    Uptrack.write_file(counterfile, str(backoff_counter)+'\n')

    # Sleep between 0 and 60s to desync the cron jobs across the
    # minute.
    time.sleep(random.randint(0,59))

def extractCommand(name):
    command = None
    if name == 'uptrack-upgrade':
        command = UPGRADE
    elif name == 'uptrack-install':
        command = INSTALL
    elif name == 'uptrack-remove':
        command = REMOVE
    elif name == 'uptrack-show':
        command = SHOW
    else:
        logging.error("I don't know what you want me to do.")
        sys.exit(-1)
    return command

def checkCommand(command):
    """Verify that command is allowed in combination with current options. """
    if command == UPGRADE and not config.allow_net:
        logging.error("Sorry, upgrading requires a network connection.")
        logging.error("(Run this command again without --no-network?)")
        sys.exit(1)
    if (command == REMOVE and not config.all) and not config.allow_net:
        logging.error("Sorry, removing individual updates requires a network connection.")
        logging.error("(Run this command again without --no-network?)")
        logging.error("")
        logging.error("If you wish to remove all updates, run this command again")
        logging.error("with --all (this does not require a network connection).")
        sys.exit(1)
    if config.uninstall and command != REMOVE:
        logging.error("--uninstall may only be used with uptrack-remove.")
        sys.exit(1)
    if config.available and command != SHOW:
        logging.error("--available may only be used with uptrack-show.")
        sys.exit(1)
    if config.all and config.args:
        logging.error("Specifying an update as well as --all makes no sense!")
        sys.exit(1)
    if config.available and config.options.count:
        logging.error("Using --available and --count at the same time is not supported.")
        sys.exit(1)

def needs_access_key(command, config):
    """Indicates if the user is both missing an access key and needs one
    for the current operation."""
    if not config.allow_net:
        return False
    elif command == REMOVE and config.uninstall:
        return False
    else:
        return config.accesskey in ['', 'INSERT_ACCESS_KEY']

def main(program, args):
    global config
    global lock
    global local, repo
    global logger

    os.environ['PATH'] = os.environ['PATH'] + ":/usr/sbin:/sbin"

    try:
        config = UptrackClientConfig(program, args)
        logger.configure(config)
        config.checkDeprecatedOptions()
    except Uptrack.ResultException, e:
        logging.error("Error loading configuration file:")
        logging.error(e.result.message)
        sys.exit(e.result.code)

    if config.options.show_version:
        print "%s" % __version__
        sys.exit(0)

    if config.options.check_init:
        if config.disabled or not config.install_on_reboot:
            sys.exit(1)
        sys.exit(0)

    os.umask(0022) # GUI needs to be able to read status files etc.

    Uptrack.initCurl(config)

    initializeDBus()

    logging.debug("")
    logging.debug("Client invoked as: %s %s" % (program, ' '.join(args)))

    command = extractCommand(os.path.basename(program))
    if config.init == 'early':
        command = INIT

    checkCommand(command)

    Uptrack.mkdirp(config.local)
    Uptrack.mkdirp(os.path.join(config.local, 'updates'))

    if config.cron:
        desync()

    lock = getLock()
    if lock is False:
        logging.debug("Unable to acquire the Uptrack repository lock: %s",
                      config.lockfile)
        logging.error("""\
It appears that another Uptrack process is currently running on this
system. Please wait a minute and try again.  If you are unable to
resolve this issue, please contact %s.""" % (Uptrack.BUG_EMAIL,))
        sys.exit(1)

    ## Check that we have an access key, before going any further.
    if needs_access_key(command, config) and os.path.exists(AUTOGEN_FLAG_FILE):
      accepted = False
      if config.accept_tos:
          accepted = True
      elif not config.init and os.isatty(sys.stdin.fileno()):
        tos = Uptrack.read_file(TOS_FILE)
        p = subprocess.Popen(['more'], stdin=subprocess.PIPE)
        p.communicate('In order to use the Ksplice Uptrack service, you must \n'
                      'agree to the Ksplice Uptrack terms of service:\n\n%s' % tos)
        while True:
          choice = raw_input('Do you agree to the Ksplice Uptrack terms of service? [yes|no] ').strip().lower()
          if choice == 'yes':
            accepted = True
            break
          elif choice == 'no':
            accepted = False
            break

      if accepted:
        logging.warning('Requesting access key... (this may take a few moments)')
        s = StringIO.StringIO()

        try:
            code = Uptrack.download(Uptrack.getCurl(), AUTOGEN_URL,
                                    '/dev/null', stringio=s)
            if code != 200:
                logging.error('The Ksplice Uptrack server gave a response code of %d\n'
                              'while requesting access key.  Please contact\n'
                              '%s for assistance.' % (code, Uptrack.BUG_EMAIL,))
                sys.exit(1)
        except pycurl.error, e:
            logging.debug("cURL error %d (%s) while requesting access key."
                          % (e[0], e[1]))
            logging.debug(traceback.format_exc())
            logging.error(Uptrack.resultFromPycurl(config, e).message)
            sys.exit(1)

        p = subprocess.check_call(['sed', '-i', '-e', 's/^\s*accesskey\s*=.*/accesskey = %s/' % s.getvalue(), '/etc/uptrack/uptrack.conf'])
        logging.info('Access key successfully requested')
        releaseLock()
        # We're just marking ourselves as accepted for the GUI
        if config.accept_tos:
            sys.exit(0)

        # Restart with the updated config file
        os.execv(sys.argv[0], sys.argv)
      else:
        logging.info('You must accept the Ksplice Uptrack terms of service\n'
                     'in order to use the service.')
        sys.exit(Uptrack.ERROR_MISSING_KEY)

    # Some initialization has to happen inside the lock to serial accesses.
    try:
        config.initWithLock()
    except Uptrack.ResultException, e:
        logging.error("Error loading configuration file:")
        logging.error(e.result.message)
        sys.exit(e.result.code)

    config.notify.ClientStartStop('START')
    repo = UptrackRepo(config)
    local = Uptrack.LocalStatus(config, repo, logger)

    if needs_access_key(command, config):
        res = Uptrack.Result()
        res.code = Uptrack.ERROR_MISSING_KEY
        res.message = "You must specify an access key to use the service.\n"
        res.message += ("Please add your key to %s" % Uptrack.UPTRACK_CONFIG_FILE)
        quit(res)

    will_download = False

    if command != SHOW and config.allow_net and not config.uninstall:
        isOk(repo.validateServer())
        isOk(repo.handleStatus())
        will_download = True
    else:
        res = repo.parsePackageList()
        if res and res.code == Uptrack.ERROR_NO_NETWORK and command == SHOW and \
               config.options.count and not config.allow_net:
            # uptrack-show --count --no-network (invoked by removal hooks)
            #
            # No packages.yml file exists on disk.  Assuming packages.yml
            # wasn't deleted, there can be no updates installed.
            logging.info("0")
            sys.exit(0)
        if res and res.code and command == SHOW:
            logging.error("Unable to read the package list.\n"
                          "Please run 'uptrack-upgrade -n' to download "
                          "the latest package list.")
            sys.exit(1)
        if res and res.code and command == INIT:
            # There's no packages.yml, but we still need to clean /var/run/{ksplice,uptrack}
            doInitClean(local)
            if res.code == Uptrack.ERROR_NO_NETWORK:
                # User rebooted into a new kernel, so don't be alarmed
                # that there's no packages.yml
                res.code = 0
                res.newkernel = True
                res.message = "Ksplice Uptrack: booting into a new kernel, so not installing any updates."
                quit(res)

        isOk(res)

    if not os.path.isdir('/sys/module') and (
        command != SHOW or not config.options.count):
        # Put this check after they've confirmed it is a supported kernel,
        # so that we don't need to worry about CONFIG_MODULES being off.
        if os.path.exists('/proc/vz'):
            message = ("Error: You are running Ksplice Uptrack inside a Virtuozzo/OpenVZ container,\n"
                       "  but it needs to run on the hardware node instead.\n"
                       "\n"
                       "  If you have purchased a virtual private server (VPS) from a hosting company,\n"
                       "  please contact them and ask them to purchase Ksplice Uptrack for their VPS\n"
                       "  systems. If you are the VPS provider, please install Ksplice Uptrack on the\n"
                       "  hardware node rather than in a container.\n"
                       "  If you need help resolving this issue, please contact %s."
                    % (Uptrack.BUG_EMAIL,))
        else:
            message = ("Error: The directory /sys/module was not found.\n"
                       "  You must have the /sys filesystem mounted in order to use Ksplice Uptrack.\n"
                       "  If you are running inside a chroot, you must mount /sys inside the chroot.\n"
                       "  This could also be caused by an old or non-standard system configuration.\n"
                       "  If you need help resolving this issue, please contact %s."
                    % (Uptrack.BUG_EMAIL,))

        res = Uptrack.Result(Uptrack.ERROR_SYS_NOT_MOUNTED, message)
        quit(res)

    if will_download:
        isOk(repo.downloadAll())

    if config.disablecmd and command == INIT:
        file('/etc/uptrack/disable', 'w')
        config.disabled = True
    if config.disabled and command != SHOW:
        res = Uptrack.Result()
        res.code = 1
        res.message = "Uptrack disabled by system administrator, remove /etc/uptrack/disable to enable."
        quit(res)

    if repo.expired:
        if command != SHOW and not (command == REMOVE and config.all):
            if command == REMOVE:
                msg = "Removing individual updates is disabled."
            else:
                msg = "Installing updates is disabled."

            quit(Uptrack.Result(Uptrack.ERROR_EXPIRED, msg))

    if command == INIT:
        res = doInit(repo, local)
    elif command == UPGRADE:
        res = doUpgrade(repo, local)
    elif command == INSTALL:
        res = doInstall(repo, local, config.args)
    elif command == REMOVE:
        # Special case: We are able to remove all updates using the
        # saved remove_plan without going to the server.

        # We do this for 'remove --no-network', if our access key has
        # expired (in which case we won't be able to reach the
        # server), or when uninstalling the package, so we can be
        # removed without network.
        if config.uninstall or \
              config.all and (not config.allow_net or repo.expired):
            res = doOfflineRemoveAll(repo, local)
        else:
            res = doRemove(repo, local, config.args)
    elif command == SHOW:
        res = doShow(repo, local, config.args)

    if res and command in [ INIT, UPGRADE, INSTALL, REMOVE ]:
        if res.code == Uptrack.ERROR_USER_NO_CONFIRM:
            quit(res)
        if len(res.succeeded):
            logging.debug("")
            logging.debug("The following actions were successful:")
            for act in res.succeeded:
                logging.debug("%s %s" % (act.command, act.update))
        if len(res.failed):
            logging.info("")
            logging.error("The following actions failed:")
            for act in res.failed:
                logging.error("%s %s" % (act.command, act.update))
                logging.error(prettyResult(act))
                commands = {INSTALL: 'apply', REMOVE: 'undo'}
                logging.debug("Message:\n" + act.message)
            logging.error("")
            res.code = 1

    quit(res)

if __name__ == "__main__":
    try:
        logger = Logger()
    except Exception:
        print >>sys.stderr, "Unable to set up the logger."
        if os.getuid() != 0:
            print >>sys.stderr, "The Uptrack client must be run as root."
        sys.exit(1)

    try:
        main(sys.argv[0], sys.argv[1:])
    except KeyboardInterrupt:
        logging.error("Interrupted!")
        logging.debug("", exc_info=1)
        sys.exit(1)
    except SystemExit:
        raise
    except Exception:
        # Catch unhandled exceptions and report them to the server.
        res = Uptrack.Result(Uptrack.ERROR_INTERNAL_ERROR, traceback.format_exc())
        if local is None:
            logging.error("Unexpected error starting the Uptrack client.")
            logging.error("Please submit a copy of %s to %s." % (LOGFILE, Uptrack.BUG_EMAIL))
            logging.debug(res.message)
            sys.exit(-1)
        try:
            local.writeOutStatus(res, None, None, None)
        except SystemExit:
            raise
        except Exception:
            pass

        logging.debug("Unhandled exception", exc_info=1)
        logging.error("Unexpected error.")
        logging.error("Please submit a copy of %s to %s." % (LOGFILE, Uptrack.BUG_EMAIL))
        sys.exit(-1)

"""
=head1 NAME

uptrack - Manage Ksplice rebootless kernel updates

=head1 SYNOPSIS

B<uptrack-upgrade> [I<OPTION>]

B<uptrack-install> [I<OPTION>] I<id>...

B<uptrack-remove> [I<OPTION>] I<id>...

B<uptrack-show> [I<OPTION>] [I<id>...]

=head1 DESCRIPTION

The Uptrack command-line tools manage the set of Ksplice rebootless
kernel updates installed on your system. There are four major modes of
operation:

=over 4

=item B<uptrack-upgrade>

Downloads and installs the latest Ksplice updates available for your system.

=item B<uptrack-install>

Takes as arguments the update IDs to install, and installs them,
downloading them if necessary.

=item B<uptrack-remove>

Takes as arguments the update IDs to remove, and removes them.

=item B<uptrack-show>

If invoked without additional arguments, shows the list of Ksplice
updates currently installed.  If update IDs are passed as arguments,
displays the status of those updates as well as the detailed
information associated with them.

=back

=head1 OPTIONS

=over 4

=item B<-v>, B<--verbose>

Provide more detail about what the program is doing.

=item B<-q>, B<--quiet>

Do not print status messages.

=item B<-y>

Assume "yes" to all user prompts.

=item B<-n>

Assume "no" to all user prompts.

=item B<--all>

Take action for all of the IDs that Uptrack knows about, instead of
specifying them at the command-line.

For uptrack-show, this will list both installed updates and available
updates.

=item B<--available>

With C<uptrack-show>, instead of showing installed updates, shows the
available updates.

=item B<--count>

With C<uptrack-show>, instead of showing installed updates, print the
number of updates installed.

=item B<--wait=N>

When installing or removing a sequence of updates, wait B<N> seconds
after processing each update before processing the next one.

=item B<-V>, B<--version>

Print the version information and exit.

=back

=head1 FILES

=over 4

=item I</etc/uptrack/uptrack.conf>

Configuration file for Uptrack.

=item I</etc/uptrack/disable>

If this file exists, Uptrack will refuse to install or remove updates.
If 'nouptrack' is passed on the kernel command line, then no updates
will be installed at boot time, and I</etc/uptrack/disable> will
automatically be created during the boot process.

=back

=head1 BUGS

Please report bugs to <support@ksplice.com>.

=head1 AUTHORS

Waseem Daher and Tim Abbott

=head1 COPYRIGHT

Copyright (C) 2008-2011  Ksplice, Inc.

This is free software and documentation.  You can redistribute and/or modify it
under the terms of the GNU General Public License, version 2.

=cut
"""
