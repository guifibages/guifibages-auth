#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Guifibages auth client for freeradius
#
# Copyright 2012 Associació d'Usuaris Guifibages
# Author: Ignacio Torres Masdeu <ignacio@xin.cat>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
import os
import json
import httplib

def log(logstring):
    with open("/var/log/freeradius/guifibages-radius-auth.log", "a") as myfile:
        myfile.write("%s [%s] %s\n" % (datetime.now(),
            os.getpid(), logstring))

def ssocheck(username,ip):
    try:
        h = httplib.HTTPSConnection('webfront01.guifibages.net')
        h.request("GET", "/api/user/%s" % username)
        res = h.getresponse()
        status = False
        if res.status == 200:
            rdata = res.read()
#            log("ssocheck %s %s: %s" % (username, ip, rdata))
            data = json.loads(rdata)
            if ip in data:
                status = True
        h.close()
        return status
    except Exception, error:
        log ("ssocheck Error: %s" % error)

def accept(reason,router,username,ip):
    log("%s Login to %s: %s %s" % (reason, router, username, ip) )
    print "Auth-Type := Accept"


def trusted(username,ip):
    trusted_users=[
            'ignacio.torres',
            'albert.homs',
            'francisco.delaguila',
            'gil.obradors',
            'josep.figueres',
            'xavier.martinez'
            ]
    trusted_stations=[
            '10.228.17.24']
    if username in trusted_users and ip in trusted_stations:
        return True
    return False


def validate():
    if not 'Calling-Station-Id' in os.environ:
        exit(0)
    rusername=os.environ['User-Name']
    rip=os.environ['Calling-Station-Id']
    rrouter=os.environ['NAS-Identifier']

    if trusted(rusername,rip):
        accept("Trusted",rrouter,rusername,rip)
        exit(0)
    elif ssocheck(rusername,rip):
        accept("SSO",rrouter,rusername,rip)
    exit(0)

validate()
exit(0)
