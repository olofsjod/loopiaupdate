"""

 ##############
# loopiaupdate #
 ##############

Copyright 2017  Olof Sjödin

Licensed with GPL v3, see the LICENSE file.

"""
BUILD_VERSION="v1.1"

import os
import sys
import urllib.request
import xmlrpc.client
from os.path import expanduser, exists

class LoopiaAPI:
    def __init__(self, u, p):
        self.username = u
        self.password = p

        global_domain_server_url = 'https://api.loopia.se/RPCSERV'
        self.client = xmlrpc.client.ServerProxy(global_domain_server_url)

    def addZoneRecord(self, IP, DOMAIN, SUBDOMAIN, TTL, PRIORITY):
        record_obj = LoopiaAPI.createRecordObj(type="A", ttl=TTL,
                                               priority=PRIORITY,
                                               rdata=IP, id=0)
        resp = self.client.addZoneRecord(self.username, self.password, DOMAIN,
                                         SUBDOMAIN, record_obj)
        return resp

    def getSubdomains(self, domain):
        resp = self.client.getSubdomains(self.username, self.password, domain)
        return resp

    def createDomain(self, **kwargs):
        if 'domain' in kwargs:
            resp = self.client.addDomain(self.username, self.password, **kwargs)
            print(resp)

    def createRecordObj(type,ttl,priority,rdata,id):
        recordObj = dict()
        recordObj['type'] = type
        recordObj['ttl'] = ttl
        recordObj['priority'] = priority
        recordObj['rdata'] = rdata
        recordObj['id'] = id
        return recordObj

    def createSubdomain(self, domain, subdomain):
        print("Adding subdomain %s.%s" % (subdomain, domain))
        resp = self.client.addSubdomain(self.username, self.password, domain, subdomain)
        return resp

    def modifyRecordObj(recordObj, **kwargs):
        for key, val in kwargs.items():
            if key == "type":
                recordObj['type']=val
            elif key == "ttl":
                recordObj['ttl']=val
            elif key == "priority":
                recordObj['priority']=val
            elif key == "rdata":
                recordObj['rdata']=val
            elif key == "id":
                recordObj['id']=val
        return recordObj

    def setIP(self, ip, domain, subdomain):
        print("Setting IP %s for %s.%s" % (ip, subdomain,domain))

        resp = []
        if subdomain in self.getSubdomains(domain):
            recordObj = self.client.getZoneRecords(self.username, self.password, domain,
                    subdomain)

            if len(recordObj) > 0:
                LoopiaAPI.validateStatus(recordObj[0])

            type_A_exist = False
            for rObj in recordObj:
                if rObj['type'] == 'A':
                    type_A_exist = True
                    newRecordObj = LoopiaAPI.modifyRecordObj(rObj,rdata=ip)
                    resp.append(self.client.updateZoneRecord(self.username, self.password,
                        domain, subdomain, newRecordObj))
            if not type_A_exist:
                resp.append(self.addZoneRecord(ip, domain, subdomain, 3600, 0))
        else:
            resp.append(self.createSubdomain(domain, subdomain))
            resp.append(self.addZoneRecord(ip, domain, subdomain, 3600, 0))

        print("Response:", end="")
        for s in resp:
            print(s, end=", ")
        print("\n")

    def validateStatus(STATUS):
        if STATUS == "AUTH_ERROR":
            print("ERROR: Authentication error. Please update your username and"
                  " password. Aborting.")
            exit()
        elif STATUS == "OK":
            return
        elif STATUS == "DOMAIN_OCCUPIED":
            print("ERROR: Domain is not available.")
        elif STATUS == "RATE_LIMITED":
            print("ERROR: Maximum request rate reached. Aborting.")
            exit()
        elif STATUS == "BAD_INDATA" or STATUS == "UNKNOWN_ERROR":
            print("ERROR: Bad indata. Please file a bug.")
            exit()
        else:
            return STATUS


def help():
    print("\n\nloopiaupdate.py %s\n"
          "Author: Olof Sjödin <me@olofsjodin.se>\n" % BUILD_VERSION)
    print("loopiaupdate.py retrieves the ip and updates a given domain"
          " and/or subdomain at Loopia without\nhaving to access the web user"
          " interface.")
    print("This script have some nice features, e.g. it will add a subdomain if it"
          " does not exist.\n")
    print("Syntax: python3 loopiaupdate.py [-h] [-u username -p password]",
          "[--ip 123.123.123.123] <domainname>")


def getCredentials(f_path):
    if not exists(f_path):
        print("ERROR: The configuration file (%s) does not exist!"
              "Aborting." % f_path)
        exit()

    usrpw = open(f_path, 'rU').readlines()

    username = ""
    password = ""

    for u_p in usrpw:
        if len(u_p) >= 9:
            tmp = u_p[:8] # 'username' '=...'
            if "username" in tmp and username == "":
                username = u_p[9:].strip("\n") # 'username=' '...'
            elif "password" in tmp and password == "":
                password = u_p[9:].strip("\n")
            else:
                print("ERROR: Syntax error in the configuration file! Aborting.")
                help()
                exit()

    return (username, password)

def getArguments():
    ARGV = sys.argv
    _USERNAME = ""
    _PASSWORD = ""
    _IP = ""

    if "-h" in ARGV:
        help()
        exit()

    if "-u" in ARGV:
        k = 0
        for i in range(len(ARGV)):
            if ARGV[i] != "-u":
                pass
            else:
                k=i+1
                break
        _USERNAME = ARGV[k]
    if "-p" in ARGV:
        k = 0
        for i in range(len(ARGV)):
            if ARGV[i] != "-p":
                pass
            else:
                k=i+1
                break
        _PASSWORD = ARGV[k]
    if "--ip" in ARGV:
        k = 0
        for i in range(len(ARGV)):
            if ARGV[i] != "--ip":
                pass
            else:
                k=i+1
                break
        _IP = ARGV[k]

    if (len(ARGV)-1) == 0:
        print("ERROR: You must set a domain. Aborting.")
        help()
        exit()

    _DOMAIN = ARGV[len(ARGV)-1]
    return (_USERNAME, _PASSWORD, _DOMAIN, _IP)

def getIP():
    try:
        # Using http://icanhazip.com to get external ip
        return urllib.request.urlopen('http://icanhazip.com').read().decode().strip("\n")
    except:
        print("ERROR: The script can't retrieve the ip (check your internet"
              " connection). Aborting")
        exit()

def isFileReadableByOthers(_f):
    mask = os.stat(_f).st_mode

    # Test if the file has right permissions
    readableByAll=292
    readableByGroup=288
    # readableByUser=256

    # Will use the bitwise operation AND to determine if the
    # file has right permissions.
    if ((mask & readableByAll) == readableByAll
            or (mask & readableByAll) == readableByGroup): # '444' in octal
        return True
    else:
        return False

def partitionDomain(domain):
    _subdomain = ""
    _domain = ""
    tmp = domain.split(".")
    if len(tmp) == 2:
        _subdomain = "*"
        _domain = domain
    else:
        _domain = ".".join(tmp[(len(tmp)-2):])
        _subdomain = ".".join(tmp[:len(tmp)-2])

    return (_domain, _subdomain)

def error(msg):
    print(msg)
    help()
    exit()

def retUsrPwFromCredentials():
    HOME = expanduser("~")
    CREDENTIALS_PATH="%s/.loopiaupdate/credentials" % HOME

    # Check if the credential file exist. If not: print an error.
    if not exists(CREDENTIALS_PATH):
        error("ERROR: The file %s does not exist, please create it." %
                CREDENTIALS_PATH)

    # Check if the file is readable by others. If it is: print an error.
    if isFileReadableByOthers(CREDENTIALS_PATH):
        error("ERROR: Your credentials can't be readable by other than the user. Aborting.")

    # Retrieve the user and password from credential file.
    USERNAME, PASSWORD = getCredentials(CREDENTIALS_PATH)

    # If one of the parameters is empty print an error.
    if USERNAME == "" or PASSWORD == "":
        error("ERROR: You have to provide username and password. Aborting.")

    return (USERNAME, PASSWORD)

def main():
    # Retrieve arguments from user input
    USERNAME, PASSWORD, DOMAIN, IP = getArguments()

    # Check if user hasn't provided a username or password. If so use the
    # credential file.
    if USERNAME == "" or PASSWORD == "":
        USERNAME, PASSWORD = retUsrPwFromCredentials()

    q = partitionDomain(DOMAIN)

    loopia = LoopiaAPI(USERNAME, PASSWORD)

    if IP == "":
        loopia.setIP(getIP(), *q)
    else:
        loopia.setIP(IP, *q)

if __name__ == "__main__":
    main()
