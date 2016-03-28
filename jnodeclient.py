#!/usr/bin/env python
import getopt
import json
import uuid
import socket
import time
import subprocess
import struct
import os.path
import sys
from sys import argv

def usage():
  print """
         _       _        _   _      _        _____ _ _            _
        | |     | |      | \ | |    | |      / ____| (_)          | |
        | | __ _| | _____|  \| | ___| |_    | |    | |_  __  _ __ | |_
    _   | |/ _` | |/ / _ \ . ` |/ _ \ __|   | |    | | |/ _ \ '_ \| __|
   | |__| | (_| |   <  __/ |\  |  __/ |_    | |____| | |  __/ | | | |_
    \____/ \__,_|_|\_\___|_| \_|\___|\__|    \_____|_|_|\___|_| |_|\__|
  """
  print
  print "Usage: jnodeclient.py --target=<host> --port=<port> and more!"
  print "-h --help                      - Display this help"
  print "-t --target                    - Define name or IP for connecting to server"
  print "-p --port                      - Define port for connecting to server"
  print "-u --uuid                      - Remote Node UUID, required for sending requests to remote node"
  print "-c --cmd                       - Send command to be executed on remote node"
  print "-m --method                    - Request type"
  print "-r --role                      - Role type (privilege escalation)"
  print "-x --xhost                     - Hostname of the Remote Node"
  print "-d --data                      - Generic data cell for data transfer"
  print "-l --location                  - Location information for savedata"
  print
  print
  print "Examples: "
  print "./jnodeclient.py --target=ts3.fi --port=9998 --xhost=argon096 --method=uuids"
  print "./jnodeclient.py --target=ts3.fi --port=9998 --method=remcmd --cmd=\"ls -la /var/log/syslog\" --role=master --xhost=argon096 --uuid="
  print "./jnodeclient.py --target=ts3.fi --port=9998 --method=download --role=master --xhost=argon096 --location=/var/log/syslog --uuid="
  print "./jnodeclient.py --target=ts3.fi --port=9998 --method=upload --role=master --xhost=argon096 --location=/var/log/syslog --uuid="

  sys.exit(0)

def sendmsg(conn, msg):
  # 4 byte struct prefix for len(msg)
  msg = struct.pack('>I', len(msg)) + msg
  conn.sendall(msg)

def recvmsg(conn):
  raw_msglen = recvall(conn, 4)
  if not raw_msglen:
    return None
  #unpack struct to integer
  msglen = struct.unpack('>I', raw_msglen)[0]
  return recvall(conn,msglen)

def recvall(conn, n):
  data = ''
  while len(data) < n:
    packet = conn.recv(n - len(data))
    if not packet:
      return None
    data += packet
  return data

def connect(target, port):
  try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target, port))
    return client
  except:
    print "[x] Failed to connect to server"
    return False

def idle(msg,conn):
  if msg == "idle":
    print "[+] Going idle..."
    idle = True
    sendmsg(conn, "idle")
  while idle:
    if recvmsg(conn) != "idle":
      sendmsg(conn,"awake")
      idle = False
      print "Idle is %s" % idle
      return recvmsg(conn)
    else:
      sendmsg(conn, "idle")
      idle = True


def run_cli(cmd):                                                                                                                                                                                                                  [120/9154]
  proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
  procout = proc.stdout.read()
  return procout

def state_ready(conn,uid,hostname):
  msg=init_msg("ready",uid,hostname,"","","","")
  sendmsg(conn, msg)
  print "[+] Node ready for action!"
  return True

def request_handler(conn,uid,hostname,method,location,data,cmd,role):
  request={}
  request["uuid"]=uid
  request["host"]=hostname
  request["method"]=method
  request["location"]=location
  request["cmd"]=cmd
  request["role"]=role
  request["data"]=data
  if method == "upload":
    if findFile(location):
      f=open(location,"rb")
      file=f.read()
      f.close()
      request["data"]=file
  msg=json.dumps(request)
# HIDE EXCESS PRINTING FROM CLI
# HIDE EXCESS PRINTING FROM CLI
#  print "[+] Sending %s package with following info:\n" % method
#  print "[+] UUID      : %s" % request["uuid"]
#  print "[+] Host      : %s" % request["host"]
#  print "[+] Method    : %s" % request["method"]
#  print "[+] Location  : %s" % request["location"]
#  print "[+] Command   : %s" % request["cmd"]
#  print "[+] Role      : %s" % request["role"]
#  if request["data"]:
#    print "[+] Data      : \n%s" % request["data"]
#  else:
#    print "[+] Data      : %s" % request["data"]
  if method == "shell":
    try:
      sendmsg(conn, msg)
    except:
      print "[FAIL] Failed to send data"
    while True:
      data=recvmsg(conn)
      print "Jake! > %s" % data
      input=raw_input("Jake! > ")
      sendmsg(conn,input)

  try:
    sendmsg(conn, msg)
  except:
    print "[FAIL] Failed to send data"
  try:
    ans=json.loads(recvmsg(conn))
    uid=ans["uuid"]
    host=ans["host"]
    method=ans["method"]

    location=ans["location"]                                                                                                                                                                                                        [60/9154]
    data=ans["data"]
    cmd=ans["cmd"]
    role=ans["role"]
# HIDE EXCESS PRINTING FROM CLI
# HIDE EXCESS PRINTING FROM CLI
#    print "\n\n[DONE] Result:\n"
#    print
#    print "UUID      : %s" % ans["uuid"]
#    print "Host      : %s" % ans["host"]
#    print "Method    : %s" % ans["method"]
#    print "Location  : %s" % ans["location"]
#    print "Command   : %s" % ans["cmd"]
#    print "Role      : %s" % ans["role"]
    if method == "ack_up":
      print "[+] Upload complete"
      sys.exit()
    if method == "download":
      local=raw_input("Give save path for incoming file: ")
      f=open(local,"wb")
      f.write(data)
      f.close()
      print "[+] File saved to %s" % local
    if method == "uuids":
      print "\nListing UUIDS:"
      print data[0]
    if method == "remcmd":
      print ans["data"]
  except:
    print "[FAIL] No response from master."
    sys.exit()

def findFile(file):
  abs=os.path.split(file)
  if os.path.exists(abs[0]):
    if os.path.exists(file):
      return True
  else:
    print "[DEBUG] File does NOT exist!"
    return False

def init_msg(method,uid,host,location,data,cmd,role):
  request={}
  request["method"]=method
  request["uuid"]=uid
  request["host"]=host
  request["location"]=location
  request["data"]=data
  request["cmd"]=cmd
  request["role"]=role
  msg=json.dumps(request)
  return msg

def main():
  global target
  global port
  global hostname
  global uid
  global method
  global location

  global cmd
  global data
  global role
  # Set global defaults
  location   = False
  target     = False
  port       = False
  cmd        = False
  uid        = False
  method     = False
  data       = False
  role       = False
  hostname   = False

  if not len(sys.argv[1:]):
    usage()
  #CMDline options
  try:
    opts, args = getopt.getopt(sys.argv[1:],"h:t:p:c:u:m:d:r:x:l", ["help","target=","port=","cmd=","uuid=","method=", "data=", "role=", "xhost=","location="])
  except getopt.GetoptError as err:
    print str(err)
    usage()
  for o,a in opts:
    if o in ("-h","--help"):
      usage()
    elif o in ("-t", "--target"):
      target = a
    elif o in ("-c", "--cmd"):
      cmd = a
    elif o in ("-p", "--port"):
      port = int(a)
    elif o in ("-u", "--uuid"):
      uid = a
    elif o in ("-m", "--method"):
      method = a
    elif o in ("-d", "--data"):
      data = a
    elif o in ("-r", "--role"):
      role = a
    elif o in ("-x", "--xhost"):
      hostname = a
    elif o in ("-l", "--location"):
      location = a
    else:
      assert False,"Unhandled Option"

  conn=connect(target,port)
  if not conn:
#    print "[+] Connection established"
#  else:
    print "[-] Failed to establish connection"
  #while True:
  request_handler(conn,uid,hostname,method,location,data,cmd,role)
    #request_handler,(conn,uid,hostname)


if __name__ == "__main__":
  main()


