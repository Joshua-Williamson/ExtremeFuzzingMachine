import socket
import time 

time.sleep(3)
#Debugging script
#False to mimic ./neuzz, True to minic nn.py
send=False
HOST = '127.0.0.1'
PORT = 12012

#Initalise server config
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Such that the OS releases the port quicker for rapid rerunning
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
if send==True:
    #Attatch to ip and port
    sock.bind((HOST, PORT))
    #Waits for neuzz execution
    sock.listen(1)
    conn, addr = sock.accept()
    conn.sendall(b"start")

else:
    sock.connect((HOST,PORT))