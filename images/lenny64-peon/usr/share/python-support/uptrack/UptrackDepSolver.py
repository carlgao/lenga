#!/usr/bin/env python

# Copyright (C) 2008-2010 Ksplice, Inc.
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
#
# Not a Contribution for purposes of the Fedora Project Individual Contributor
# License Agreement

import datetime
import pycurl
import cStringIO as StringIO
import logging
import posixpath

import Uptrack

class UptrackDepSolver(object):
    def __init__(self,
                 local,
                 installed_update_ids, locked_update_ids):

        self.local_status = local
        self.config = local.client_config
        self.server_url = posixpath.join(self.config.remote, 'actions')
        self.installed_update_ids = installed_update_ids
        self.locked_update_ids = locked_update_ids

    def _sendRequest(self, request):
        contents = Uptrack.yaml_dump(request, version=(1, 1),
                                     explicit_start = True, explicit_end = True)

        try:
            s = StringIO.StringIO()
            c = Uptrack.getCurl()
            c.setopt(pycurl.URL, self.server_url)
            c.setopt(pycurl.HTTPPOST, [('request', contents)])
            c.setopt(pycurl.WRITEFUNCTION, s.write)
            c.perform()
        except:
            # We can be somewhat sloppier in error reporting here,
            # because we already checked for network and key validity
            # when fetching packages.yml.
            logging.debug("Request to the dependency solver failed", exc_info=1)
            raise Uptrack.ResultException(Uptrack.ERROR_NO_NETWORK,
                    "An error occurred requesting upgrade plans from "
                    "the server. Check your\nnetwork connection and try again.")
        rcode = c.getinfo(pycurl.RESPONSE_CODE)
        if rcode != 200:
            logging.debug("Received HTTP %03d from the server" % rcode)
            if 500 <= rcode <= 599:
                raise Uptrack.server_error_exception
            else:
                raise Uptrack.ResultException(Uptrack.ERROR_INTERNAL_SERVER_ERROR,
                        "The Ksplice Uptrack server reported the error:\n" +
                         s.getvalue())
        response = Uptrack.yaml_load(s.getvalue())

        if 'Backoff' in response:
            self.config.updateBackoff(response['Backoff'])

        if ('RegenerateUUID' in response
            and response['RegenerateUUID']
            and not self.config.use_hw_uuid):
            self.config.newuuid = self.config.newUUID()

        if 'RemovableModules' in response:
            self.config.removableModules = response['RemovableModules']

        return response

    def getPlans(self, actions):
        req = {}
        Uptrack.Status.addIdentity(self.config, req, local_status=self.local_status)
        req['Time'] = datetime.datetime.utcnow()
        req['Command'] = {}
        req['Command']['Action'] = 'getPlansEx'
        req['Command']['Cron'] = self.config.cron
        req['Command']['Autoinstall'] = self.config.cron_autoinstall
        req['Command']['Actions'] = actions
        req['Command']['Already Installed'] = self.installed_update_ids
        req['Command']['Locked'] = self.locked_update_ids
        req['Command']['Modules Loaded'] = self.config.modules
        return self._sendRequest(req)
