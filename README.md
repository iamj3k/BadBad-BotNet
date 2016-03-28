# JakeNet
Remote management server.   
ATTN: THIS IS NOT A SECURE WAY TO CONTROL ANYTHING, USE AT YOUR OWN RISK
I AM NOT RESPONSIBLE FOR ANYTHING YOU DO WITH THIS CODE!!!

jnodeclient.py is the management CLI-client which controls the remote nodes.
jnodeserver.py is the Master server that proxys commands and keeps track(?) of the managed nodes(servers).
jnode.py is the "agent" that is to be installed on the target remote server.

HOW-TO

1. Start jnodeserver.py on your server.
2. Start jnode.py on remote linux server or linux desktop.
3. Check jnodeserver.py for registered uuid
4. Start jnodeclient.py on your laptop and start sending commands to jnodeserver.py (-h for help)


