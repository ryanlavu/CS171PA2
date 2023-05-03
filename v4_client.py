# client.py
# this process only connects to a predefined server
# it sends any input it receives from the user to the server
# and echoes any message it receives from the server to console
import socket
import threading

from os import _exit
from sys import stdout
from time import sleep
import sys

import numpy as np 

#Implement Lamport's algorithm here
def start_lamports_alg():
	#Put request at head of own queue
	

	#Counter for how many REPLY messages the client has received
	reply_counter = 0

	#Send a Request message to the other clients
	Request_string = "Request " + str(local_time) + str(ID) 
	for i in range(len(list_pid)):
		out_sock_list[list_pid[i]].sendall(bytes(Request_string, "utf-8"))


# keep waiting and asking for user inputs
def get_user_input():
	#Need to account for Transfer and Balance inputs
	while True:
		# wait for user input
		user_input = input()
		user_input_list = user_input.split()
		ID = sys.argv[1]
		
		if user_input == "":
			# close socket before exiting
			out_sock.close()
			#print("exiting program")
			# flush console output buffer in case there are remaining prints
			# that haven't actually been printed to console
			stdout.flush() # imported from sys library
			# exit program with status 0
			_exit(0) # imported from os library
		if user_input_list[0] == "wait":
			local_time = local_time + 1
			sleep_time = int(user_input_list[1])
			sleep(sleep_time)
		if user_input_list[0] == "exit":
			# close socket before exiting
			out_sock.close()
			#print("exiting program")
			# flush console output buffer in case there are remaining prints
			# that haven't actually been printed to console
			stdout.flush() # imported from sys library
			# exit program with status 0
			_exit(0) # imported from os library
		if user_input_list[0] == "connect":
			#Manual input to connect to all the other clients
			#Outgoing connection to other clients
			for i in range(len(list_pid)):
				print("CONNECTING111")
				out_sock_list[i].connect((SERVER_IP, SERVER_PORT + list_pid[i]))

		else:
			#Balance and Transfer requests to server
			user_input_list.append("P" + str(ID))
			input_string = " ".join(user_input_list)

			if user_input_list[0] == "Balance":
				local_time = local_time + 1
				try:
					# send user input string to server, converted into bytes
					out_sock.sendall(bytes(input_string, "utf-8"))
				# handling exception in case trying to send data to a closed connection
				except EOFError as e:
					# close socket before exiting
					out_sock.close()
					#print("exiting program")
					# flush console output buffer in case there are remaining prints
					# that haven't actually been printed to console
					stdout.flush() # imported from sys library
					# exit program with status 0
					_exit(0) # imported from os library
				except KeyboardInterrupt:
					# close socket before exiting
					out_sock.close()
					#print("exiting program")
					# flush console output buffer in case there are remaining prints
					# that haven't actually been printed to console
					stdout.flush() # imported from sys library
					# exit program with status 0
					_exit(0) # imported from os library

			if user_input_list[0] == "Transfer":
				#Need to stop here and implement Lamport's Mutex Algorithm
				local_time = local_time + 1
				start_lamports_alg()
				
				try:
					# send user input string to server, converted into bytes
					out_sock.sendall(bytes(input_string, "utf-8"))
				# handling exception in case trying to send data to a closed connection
				except EOFError as e:
					# close socket before exiting
					out_sock.close()
					#print("exiting program")
					# flush console output buffer in case there are remaining prints
					# that haven't actually been printed to console
					stdout.flush() # imported from sys library
					# exit program with status 0
					_exit(0) # imported from os library
				except KeyboardInterrupt:
					# close socket before exiting
					out_sock.close()
					#print("exiting program")
					# flush console output buffer in case there are remaining prints
					# that haven't actually been printed to console
					stdout.flush() # imported from sys library
					# exit program with status 0
					_exit(0) # imported from os library
			

			

# simulates network delay then handles received message
def handle_msg(data, addr):
	# simulate 3 seconds message-passing delay
	sleep(3) # imported from time library
	# decode byte data into a string
	data = data.decode()
	data_message = data.split()
	#Let the structure of the received below messages be "MESSAGE_TYPE TIMESTAMP PID"
	#Request message for Lamport's from other client
	if data_message[0] == "Request":
		received_timestamp = data_message[1]
		received_pid = data_message[2]
		local_time = max(local_time, int(received_timestamp)) + 1

	#Reply message to reply to "Request" messages if the source client doesn't need the crit section/it's transfer timestamp is higher
	if data_message[0] == "Reply":
		received_timestamp = data_message[1]
		received_pid = data_message[2]
		local_time = max(local_time, int(received_timestamp)) + 1

	#Respond message from the server to signal block added onto blockchain, for client to tell other clients crit section is free
	if data_message[0] == "Respond":
		received_timestamp = data_message[1]
		received_pid = data_message[2]
		local_time = max(local_time, int(received_timestamp)) + 1
	
	#The message sent to other clients to say crit section is free
	if data_message[0] == "Release":
		received_timestamp = data_message[1]
		received_pid = data_message[2]
		local_time = max(local_time, int(received_timestamp)) + 1

	# echo message to console
	else:
		print(data)

def respond(conn, addr):
	#print(f"accepted connection from port {addr[1]}", flush=True)

	# infinite loop to keep waiting to receive new data from this client
	while True:
		try:
			# wait to receive new data, 1024 is receive buffer size
			data = conn.recv(1024)
		# handle exception in case something happened to connection
		# but it's not properly closed
		except:
			print(f"exception in receiving from {addr[1]}", flush=True)
			break
			
		# if client's socket closed, it will signal closing without any data
		if not data:
			# close own socket to client since other end is closed
			conn.close()
			print(f"connection closed from {addr[1]}", flush=True)
			break

		# spawn a new thread to handle message 
		# so simulated network delay and message handling don't block receive
		threading.Thread(target=handle_msg, args=(data, addr)).start()


if __name__ == "__main__":
	sleep(1) # imported from time library
	# specify server's socket address so client can connect to it
	# since client and server are just different processes on the same machine
	# server's IP is just local machine's IP
	SERVER_IP = socket.gethostname()
	SERVER_PORT = 7001
	
	ID = sys.argv[1]
	ID_int = int(ID)
	
	list_pid = [1, 2, 3]
	list_pid.pop(ID_int-1)
	
	request_q = []

	# create a socket object, SOCK_STREAM specifies a TCP socket
	# do not need to specify address for own socket for making an outbound connection
	out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# attempt to connect own socket to server's socket address
	out_sock.connect((SERVER_IP, SERVER_PORT))
	# simulate 1 seconds message-passing delay

	#Need to connect to all other clients
	#Create two more connecting sockets (for the other clients)	
	out_sock_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	out_sock_3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	out_sock_list = [out_sock_2, out_sock_3]

	#Need to set up pair of <Local Time, pid> after connecting to all other clients
	#Start clock off at time 0
	#Whenever local time changes, we need to print out on client side
	#Increment by time_pid_pair[0] = time_pid_pair[0]+1
	local_time = 0
	pid = ID_int
	time_pid_pair = np.array([0, ID_int])

	
	Hello_string = "Hello " + str(ID)
	out_sock.sendall(bytes(Hello_string, "utf-8"))

	# spawn new thread to keep waiting for user inputs
	# so user input and socket receive do not block each other
	threading.Thread(target=get_user_input, daemon=False).start()

	
	out_socks = []
	#Need to set up listening socket
	in_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	in_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	in_sock.bind((SERVER_IP, SERVER_PORT + ID_int))
	in_sock.listen()
	

	# loop to keep accepting new connections, keep looping until connected to the two other clients
	
	while len(out_socks) != 2:
		print("IN WHILE")
		try:
			# wait to accept any incoming connections
			# conn: socket object used to send to and receive from connection
			# addr: (IP, port) of connection 
			print("IN TRY")
			conn, addr = in_sock.accept()
		except:
			print("exception in accept", flush=True)
			break
		# add connection to array to send data through it later
		print("ADDING")
		out_socks.append((conn, addr))
		# spawn new thread for responding to each connection
		threading.Thread(target=respond, args=(conn, addr)).start()
	

	print("CONNECTED TO ALL OTHER CLIENTS")
	
	
	# infinite loop to keep waiting to receive new data from server
	while True:
		try:
			# wait to receive new data, 1024 is receive buffer size
			# set bigger buffer size if data exceeds 1024 bytes
			data = out_sock.recv(1024)
		# handle exception in case something happened to connection
		# but it's not properly closed
		except:
			print("exception in receiving", flush=True)
			break
		# if server's socket closed, it will signal closing without any data
		if not data:
			# close own socket since other end is closed
			out_sock.close()
			#print("connection closed from server")
			#print("exiting program")
			# flush console output buffer in case there are remaining prints
			# that haven't actually been printed to console
			stdout.flush() # imported from sys library
			# exit program with status 0
			break
			_exit(0) # imported from os library
			

		# spawn a new thread to handle message 
		# so simulated network delay and message handling don't block receive
		threading.Thread(target=handle_msg, args=(data,)).start()
