#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Guifibages auth client for Squid
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

import urllib
import base64
import syslog
import time
import ldap
import sys
from datetime import datetime
import os
import json
import httplib

def log(logstring):
    if len(logstring) == 0:
        return
    syslog.syslog("%s %s" % (sys.argv[1], logstring))

def ldapauth(username,password):
    log("ldapauth (%s,%s)" %(username, password))
    if len(username)==0:
        return False
    user_dn = "uid=%s,ou=Users,ou=auth,dc=guifibages,dc=net" % username
    try:
        l = ldap.initialize("ldaps://aaa.guifibages.net:636")
        l.simple_bind_s(user_dn,password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
    except ldap.LDAPError, error_message:
        log('LDAPError: %s' % error_message)
        return False

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

def otpcheck(ip, username,password):
    try:
        h = httplib.HTTPSConnection('webfront01.guifibages.net')
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        params = urllib.encode({'ip': ip, 'password': password})
        h.request("POST", "/api/user/%s/otp" % username, params, headers)
        res = h.getresponse()
        status = False
        if res.status == 200:
            status = True
        h.close()
        return status
    except Exception, error:
        log ("otpcheck Error: %s" % error)

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
    log(sys.argv)

log("Vamos que nos vamos")
while True:
    line = sys.stdin.readline().strip()
    if sys.argv[1] == 'auth':
        print "OK"
        continue
    el = line.split()
    try:
        ip = el[0]
        user = el[1]
        auth = urllib.unquote(el[2]).split(' ')
        b64password = base64.b64decode(auth[1])
        el.append(auth)
        (u,password) = b64password.split(':')
        el.append(u)
        el.append(password)
    except IndexError:
        log("ERR not enough values: %s" % el)
        print "ERR"
        continue
    if otpcheck(ip,user,password):
        print "OK"
        log("OK otpcheck: %s" % el)
    elif ssocheck(user,ip):
        print "OK"
        log("OK ssocheck: %s" % el)
    elif ldapauth(user,password):
        print "OK"
        log("OK ldapauth: %s" % user)
    else:
        print "ERR"
        log("ERR: %s" % el)

exit(0)
