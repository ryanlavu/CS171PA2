# server.py
# this process accepts an arbitrary number of client connections
# it echoes any message received from any client to console
# then broadcasts the message to all clients
import socket
import threading
import hashlib

from os import _exit
from sys import stdout
from time import sleep

# Setup block chain
class blockchain:
	def __init__(self) -> None:
		self.blockchain_list =  []

		pass

	def Calculate_Balances(self):
		Balances = [10, 10, 10]
		for block in self.blockchain_list:
			if block.transaction == "":
				continue
			trans_list = block.transaction.split(",")
			Balances[int(trans_list[0][1:])-1] = Balances[int(trans_list[0][1:])-1] - int(trans_list[2][1:])
			Balances[int(trans_list[1][1:])-1] = Balances[int(trans_list[1][1:])-1] + int(trans_list[2][1:])
		return Balances
	
	def Print_Balances(self):
		Balance_list = self.Calculate_Balances()
		string_to_print = ""
		#Need to print out balance of each user
		for balance_indx in range(len(Balance_list)):
			string_to_print = string_to_print+ "P" + str(balance_indx+1) + ": $" + str(Balance_list[balance_indx])
			#Check to see if need to print comma
			if(balance_indx+1 in range(len(Balance_list))):	
				string_to_print = string_to_print + ", "
		return string_to_print
	
	def Print_Blockchain(self):
		#Need to print out blockchain
		#Need to also print out the timestamps 

		string_to_print = ""
		string_to_print += "["
		for block_obj_indx in range(len(list_blockchain.blockchain_list)):
			#Print out 
			string_to_print += str(list_blockchain.blockchain_list[block_obj_indx])
			#Check to see if need to print comma
			if(block_obj_indx+1 in range(len(list_blockchain.blockchain_list))):	
				string_to_print += ", "
		string_to_print += "]"
		return string_to_print

	def add_block(self, block):
		Balance_list = self.Calculate_Balances()
		#If transaction violates the balances, give back error message
		if block.transaction == "":
			self.blockchain_list.append(block)
			print("NOT SUPPOSED TO GO IN HERE!")
			return "Success"
		transaction_list = block.transaction.split(",")
		#Assume transactions in form of P1,P2,$1
		#Preprocess to remove first character
		transaction_sender = int(transaction_list[0][1:]) - 1
		transaction_recepient = int(transaction_list[1][1:]) - 1
		transaction_amount = int(transaction_list[2][1:])
		if Balance_list[transaction_sender] - transaction_amount < 0:
			return "Insufficient Balance"
		else:
			self.blockchain_list.append(block)
			return "Success"

#Define block class
class block_obj:
	def __init__(self, previous_block, hash_previous, transaction, nonce) -> None:
		self.previous_block = previous_block
		self.hash_previous = hash_previous
		transformed_transaction = transaction.split(",")
		transformed_transaction_concat = transformed_transaction[0] + transformed_transaction[1] + transformed_transaction[2]
		self.transaction = transaction
		self.nonce = nonce

		block = self.hash_previous + transformed_transaction_concat + str(self.nonce)
		block = block.encode('utf-8')
		hashed_nonce = hashlib.sha256(block).hexdigest()
		while hashed_nonce[0] != "0" and hashed_nonce[0] != "1" and hashed_nonce[0] != "2" and hashed_nonce[0] != "3" :
			self.nonce = self.nonce + 1
			block = self.hash_previous + transformed_transaction_concat + str(self.nonce)
			block = block.encode('utf-8')
			hashed_nonce = hashlib.sha256(block).hexdigest()
		#print("NONCE = ", self.nonce)
		block = self.hash_previous + transformed_transaction_concat + str(self.nonce)
		#print("BLOCK = ", block)
		#After while loop, found a nonce that fulfills two leading zeroes in block hash

	def __str__(self) -> str:
		trans_list = self.transaction.split(",")
		#Assume transaction in form of P1,P2,$1
		#Preprocess to remove first characters
		return "(" + trans_list[0] + ", " + trans_list[1] + ", " + trans_list[2] + ", " + str(self.hash_previous) + ")"
		

list_blockchain = blockchain()
client_dict = {}

def get_user_input():
	while True:
		user_input = input()	
		token_input = user_input.split()
		#try:
		#Handle Blockchain input		
		if token_input[0] == "Blockchain":
			print(list_blockchain.Print_Blockchain(), flush=True)

		#Handle Balance input
		if token_input[0] == "Balance":
			print(list_blockchain.Print_Balances(), flush=True)

		# close all sockets before exiting
		if token_input[0] == "exit":
			in_sock.close()
			#for sock in out_socks:
			#	sock[0].close()
			#print("exiting program", flush=True)
			# flush console output buffer in case there are remaining prints
			# that haven't actually been printed to console
			stdout.flush() # imported from sys library
			# exit program with status 0
			_exit(0) # imported from os library
		
		#Wait for given amount of seconds
		if token_input[0] == "wait":
			sleep_time = int(token_input[1])
			sleep(sleep_time)
		else:
			continue
		

# simulates network delay then handles received message
def handle_msg(data, addr):
	# simulate 3 seconds message-passing delay
	#sleep(3) # imported from time library
	# decode byte data into a string
	data = data.decode()
	# echo message to console
	#print(f"{addr[1]}: {data}", flush=True)

	#Preprocess data
	data_message = data.split()
	if data_message[0] == "Hello":
		orig_client_id = int(data_message[1])
		#Initial message to server, establish client with its address
		client_dict[addr[1]] = orig_client_id
	if data_message[0] == "Balance":
		list_bal = list_blockchain.Calculate_Balances()
		client_id = int(data_message[1][1:]) - 1
		client_bal = list_bal[client_id]

		#Assume that we append message at end to include which client requested Balance
		#Message Input: Balance P2 P1
		#^ Means P1 requested Balance of P2
		send_message = "Balance: $" + str(client_bal)
		

	if data_message[0] == "Transfer":
		#Assume we append message at the end to include the client we are transferring funds from
		#Message Input: Transfer P2 $1 P1	
		#^ Means we transfer $1 from P1 to P2
		#orig_client_string = data_message[3]
		orig_client_string = "P"+str(client_dict[addr[1]])
		recepient_string = data_message[1]
		amount_dollar = data_message[2]

		#Need to reorder transaction string to fit structure
		#In order of PSender,PRecepient,$Amount
		trans_string = orig_client_string + "," + recepient_string + "," + amount_dollar

		#Check if there are any blocks on chain, if not create genesis block
		#Create genesis block
		if len(list_blockchain.blockchain_list) == 0:
			#print("HELLO")
			#Init of block will automatically find correct nonce
			genesis_block = block_obj(None, "0"*64, trans_string, 0)
			send_message = list_blockchain.add_block(genesis_block)
		else:
			block_to_look = list_blockchain.blockchain_list[-1]
			transformed_transaction = block_to_look.transaction.split(",")
			prev_trans = transformed_transaction[0] + transformed_transaction[1] + transformed_transaction[2]
			block = block_to_look.hash_previous + prev_trans + str(block_to_look.nonce)
			block = block.encode('utf-8')
			hashed_nonce = hashlib.sha256(block).hexdigest()
			#Nonce will be incremented by the block init function
			new_block = block_obj(block_to_look, hashed_nonce, trans_string, 0)
			send_message = list_blockchain.add_block(new_block)
			#orig_client_conn.sendall(bytes(output))

	# broadcast to all clients by iterating through each stored connection
	if data_message[0] == "Transfer" or data_message[0] == "Balance":
		for sock in out_socks:
			conn = sock[0]
			recv_addr = sock[1]
			# echo message back to client
			if recv_addr == addr:
				try:
					# convert message into bytes and send through socket
					conn.sendall(bytes(f"{send_message}", "utf-8"))
					#print(f"sent message to port {recv_addr[1]}", flush=True)
				# handling exception in case trying to send data to a closed connection
				except:
					print(f"exception in sending to port {recv_addr[1]}", flush=True)
					continue

# handle a new connection by waiting to receive from connection
def respond(conn, addr):
	print(f"accepted connection from port {addr[1]}", flush=True)

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
	# specify server's socket address
	# programatically get local machine's IP
	IP = socket.gethostname()
	# port 3000-49151 are generally usable
	PORT = 8000

	# create a socket object, SOCK_STREAM specifies a TCP socket
	in_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# allow reusing socket in TIME-WAIT state
	# socket will remain open for a small period of time after shutdown to finish transmission
	# which will say "socket already in use" if trying to use socket again during TIME-WAIT
	# when REUSEADDR is not set
	in_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	# bind socket to address
	in_sock.bind((IP, PORT))
	# start listening for connections to the address
	in_sock.listen()

	# container to store all connections
	# using a list/array here for simplicity
	out_socks = []
	# spawn a new thread to wait for user input
	# so user input and connection acceptance don't block each other
	threading.Thread(target=get_user_input, daemon=False).start()

	# infinite loop to keep accepting new connections
	while True:
		try:
			# wait to accept any incoming connections
			# conn: socket object used to send to and receive from connection
			# addr: (IP, port) of connection 
			conn, addr = in_sock.accept()
		except:
			print("exception in accept", flush=True)
			break
		# add connection to array to send data through it later
		#print("SERVER ADDING")
		out_socks.append((conn, addr))
		# spawn new thread for responding to each connection
		threading.Thread(target=respond, args=(conn, addr)).start()
