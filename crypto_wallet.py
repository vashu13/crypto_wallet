#!/usr/bin/python3

#IMPORT_SECTION
import hashlib
import socket
import random
import ast
import os


#INPUT_SECTION
#usr = input("Enter UserName: ")
#pswd = input("Enter Password: ")



#FUNCTION_SECTION


def save_file(key):
	try:
		with open("KEY.txt") as p:
			print("There is already a key file.... \n")
			while 1:
				new = input("Enter another name for the new file (txt file)>>  ")
				if not new.endswith(".txt"):
					new = new+".txt"
				try: 
					with open(new) as n:
						print("File already exists... ")
						pass
				except:
					save = ""
					for i in key:
						j = i+" "
						save += j
					g = open(new,"w")
					g.write(save)
					print("YOUR FILE HAS BEEN SAVED SUCCESSFULLY")
					g.close()
					break

	except:
		save = ""
		for i in key:
			j = i+" "
			save += j
		g = open("KEY.txt","w")
		g.write(save)
		g.close()
		print()
		print("YOUR FILE HAS BEEN SAVED SUCCESSFULLY")

def gen_key():
	#SET_OF_KEYWORDS
	s = ["hello","girl","boy","lot","bike","rope","ground","leaves","birds","peacock","water","fire","ice","phone","call","building","coffee","tea","juice","apple","orange","yellow","blue","green","pink"]


	#GENERATING_RANDOM_KEY
	key = list()
	key1 = list()
	print("\n")

	for i in range(12):
		key.append(random.choice(s))		#now we have a random key
	for k in range(5):
		key1.append(random.choice(s))
	
	print("\033[1;39m \nTHIS IS YOUR PRIVATE KEY\n")
	
	for j in key:
		print(j,end=" ")
	
	print()

	#GENERATING_HASH
	hashed_key = hashlib.sha256(str(key).encode('utf-8')).hexdigest()
	hashed_key1 = hashlib.sha256(str(key1).encode('utf-8')).hexdigest()
	print(hashed_key)				#now we have a signature hash for our key
	print("\n")
	print("\033[1;39m THIS IS YOUR PUBLIC HASH KEY(PUBLIC ID)")
	print("\033[1;39m YOU DON'T NEED TO SAVE THIS ONE...\n")
	print(hashed_key1)
	
	b = input("\033[1;39m Do you want to save the key locally on the system..? (y or n) ")
	if b == 'y' or b == 'Y':
		save_file(key)
		
	return key,hashed_key1

def new_user():
	while 1:
		stat = []
		usr_name = input("\033[1;39m \nEnter user name: ")
		with open(".user.txt","r") as a:
			for line in a:
				if line.strip():
					d = ast.literal_eval(line.strip())
					if d["user"] == usr_name:
						print("\033[1;31m \nUSER ALREADY EXISTS...")
						print("\033[1;31m ENTER ANOTHER USER NAME...")
						stat.append("no")
						pass
					if d["user"] != usr_name:
						stat.append("yes")
						continue
			a.close()
		if "no" not in stat:
			break
	
	pswd = ""
	pswd1 = input("\033[1;39m Enter Password: ")
	pswd2 = input("\033[1;39m Re-Enter Password: ")
	if pswd1 != pswd2:
		print("\033[1;31m \nYOUR PASSWORDS DIDN'T MATCH \nRE-ENTER YOUR PASSWORDS\n")
		while 1:
			pswd1 = input("\033[1;39m Enter Password: ")
			pswd2 = input("\033[1;39m Re-Enter Password: ")
			
			if pswd1 == pswd2:
				pswd = pswd1
				break
	if pswd1 == pswd2:
		pswd = pswd1
	while 1:
		balance = input(f"\033[1;39m \nEnter the initial amount {usr_name} wants to start with: ")
		if balance.isdigit():
			break
		if not balance.isdigit():
			print("\033[1;34;40m \nPLEASE ENTER IN DIGITS ONLY....\n")
			pass
	
	key,pubkey = gen_key()
	record = {}
	with open(".user.txt","a") as usr:
		record = {"user":usr_name,"pswd":pswd,"balance":balance,"priv_key":key,"pub_key":pubkey}
		usr.write(str(record))
		usr.write("\n")
		usr.close()

def users():
	print("\033[1;39m \nEXISTING USERS\n")
	usr = []
	with open(".user.txt","r") as f:
		for line in f:
			if line.strip():
				d = ast.literal_eval(line.strip())
				usr.append(d['user'])
		f.close()
	
	return usr

def login():
	info = {}
	stat = ["no","no"]
	usr_name = input("\033[1;39m \nEnter user name: ")
	with open(".user.txt","r") as a:
		for line in a:
			if line.strip():
				d = ast.literal_eval(line.strip())
				if d["user"] == usr_name:
					info = d
					stat[0] = "yes"
				if d["user"] != usr_name:
					pass
		a.close()
	if info == {}:
		print(f"\033[1;31m \n{usr_name} DOESN'T EXIST\n")
	if info != {}:
		while 1:
			pswd = input("\033[1;39m \nENTER PASSWORD  ")
			if info['pswd'] == pswd:
				stat[1] = "yes"
				break
			if info['pswd'] != pswd:
				print("\033[1;31m \nWRONG PASSWORD")
				pass
	return info,stat


def balance():
	info,stat =  login()
	if "no" not in stat:
		print(f"\033[1;34;40m \n{info['user']} YOUR BALANCE IS {info['balance']} COINS\n")

def del_usr():
	info,stat =  login()
	if "no" not in stat:
		lines = []
		with open(".user.txt","r") as fp:
			lines = fp.readlines()
			fp.close()
		with open(".user.txt","w") as fp:
			for number, line in enumerate(lines):
				d = ast.literal_eval(line.strip())
				if d['user'] == info['user']:
					continue
				if d['user'] != info['user']:
					fp.write(str(d)+"\n")
			fp.close()
		print("\nUSER DATA DELETED SUCCESSFULLY....\n")

def block(sender,reciever,amount):
	empty = False
	with open("block_chain.txt") as f:
		f.seek(0, os.SEEK_END)
		if f.tell():
			f.seek(0)
		else:
			empty = True
		f.close()
	
	ledger = sender+reciever+amount
	hash_ledger = hashlib.sha256(ledger.encode("utf-8")).hexdigest()
	
	if empty == False:
		pre_hash = ''
		with open("block_chain.txt","r") as file:
			lines = file.read().splitlines()
			pre_hash = lines[-1]
			file.close()
		new_block = pre_hash + hash_ledger
	if empty == True:
		new_block = hash_ledger
	
	hash_new_block = hashlib.sha256(new_block.encode("utf-8")).hexdigest()
	
	with open("block_chain.txt","a") as file:
		file.write(hash_new_block)
		file.write("\n")
		file.close()

def send():
	data = []
	info,stat =  login()
	auth = False
	check = input("\033[1;39m \nENTER YOUR PRIVATE KEY (WITH SPACES AND NO SPECIAL CHARACTERS)\nEXAMPLE: rock bird cream bone \n")
	key_list = []
	for i in check.split(" "):
		key_list.append(i)
	if key_list == info['priv_key']:
		auth = True
	if key_list != info['priv_key']:
		print("\033[1;31m \nACCESS DENIED..")
		print("\033[1;31m \nREASON : WRONG KEY OR INAPPROPRIATE FORMAT")
	transfer = True
	if "no" not in stat and transfer == True and auth == True:
		while True:
			target = input("\033[1;39m \nENTER THE USER NAME OF THE ACCOUNT YOU WANT TO  SEND CRYPTO MONEY:  ")
			usr = users()
			if target not in usr:
				print("\033[1;34;40m \nTHERE IS NO SUCH USER IN THE RECORD...")
				pass
			if target in usr:
				info1 = {}
				with open(".user.txt","r") as a:
					for line in a:
						if line.strip():
							d = ast.literal_eval(line.strip())
							if d["user"] == info["user"]:
								pass
							if d["user"] == target:
								data.append(d)
								info1 = d
							if d["user"] != target and d["user"] != info["user"]:
								data.append(d)
								pass
					a.close()
				break
		while True:
			amount = input("ENTER AMOUNT TO BE SENT :  ")
			if amount.isdigit() and int(info['balance']) > int(amount):
				break
			if not amount.isdigit():
				print("\033[1;34;40m \nPLEASE ENTER IN DIGITS ONLY....\n")
				pass
			if int(info['balance']) < int(amount):
				print("\033[1;34;40m \nNOT ENOUGH BALANCE IN YOUR ACCOUNT...\n")
				pass
			if int(info['balance']) == int(amount):
				print("\033[1;39m \nTHE AMOUNT ENTERED IS EXACTLY EQUAL TO THE BALANCE...")
				print("\033[1;31m \nYOU ARE ABOUT TO DRAIN YOUR ACCOUNT...")
				choice = input("ENTER Y TO CONTINUE AND N TO CANCEL TRANSACTION ")
				if choice == 'Y' or choice == 'y':
					break
				if choice == 'N' or choice == 'n':
					transfer = False
					return
				else:
					print("OPTION NOT IN LIST")
					pass
		new_amt = int(info['balance'])-int(amount)
		info['balance'] = str(new_amt)
		
		with open(".user.txt","w") as fp:
			for i in range(len(data)):
				fp.write(str(data[i]))
				fp.write("\n")
			fp.write(str(info))
			fp.close()
		
		head = 10
		
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((socket.gethostname(),3031))
		s.listen(5)
		
		while True:
			clientsocket,address = s.accept()
			print(f"\033[1;39m \nCRYPRO SENT TO {info1['pub_key']} SUCCESSFULLY!!  ")
			
			mess = info['pub_key']+info1['pub_key']+amount
			msg = f'{len(mess) :<{head}}'+mess
			
			clientsocket.send(bytes(msg, "utf_8"))
			clientsocket.shutdown(socket.SHUT_RDWR)
			clientsocket.close()
			
			break
		
		block(info['pub_key'],info1['pub_key'],amount)
	

def recieve():
	
	transfer = ''
	head = 10
	
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((socket.gethostname(),3031))
	
	try:
		while True:
			full_msg = ''
			new_msg = True
			while True:
				msg = s.recv(16)
				if new_msg:
					msglen = int(msg[: head])
					new_msg = False
				full_msg += msg.decode("utf-8")
				
				if len(full_msg)-head == msglen:
					transfer = full_msg[head :]
					new_msg = True
					full_msg = ''
	except:
		pass
	
	sndr = transfer[: 64]
	rcvr = transfer[64:128]
	amt = transfer[128 :]
	
	print(f"\033[1;39m  \nFROM: {sndr}\n TO: {rcvr}\n AMOUNT: {amt} COINS....\n")
	data = []
	info = {}
	with open(".user.txt","r") as a:
		for line in a:
			if line.strip():
				d = ast.literal_eval(line.strip())
				if d["pub_key"] == rcvr:
					info = d
				if d["pub_key"] != rcvr:
					data.append(d)
					pass
		a.close()
	
	new_amt = int(info['balance'])+int(amt)
	info['balance'] = str(new_amt)
	
	with open(".user.txt","w") as fp:
		for i in range(len(data)):
			fp.write(str(data[i]))
			fp.write("\n")
		fp.write(str(info))
		fp.close()
		


#creating a hidden file to store user data
try:
	with open(".user.txt") as a:
		a.close()
		pass
except:
	a = open(".user.txt")
	a.close()
finally:
	a.close()

#checking existence of file
try:
	with open('block_chain.txt') as f:
		f.close()
		pass
except:
	f = open('block_chain.txt','a')
	f.close()
finally:
	f.close()

#USER_INTERFACE

print("Hello User!!...\nAnd welcome to the Demo Crypto Wallet...\nThis model is made with the intension to let people understand how the crypto transaction works, using the simplest functions and methods possible....\nSo learn crypto transaction in a fun way")


while True:
	print("\nMENU")
	print("\033[1;32m \n1 --> ADD NEW USER\n2 --> LIST OF EXISTING USERS\n3 --> CHECK BALANCE\n4 --> SEND CRYPTO\n5 --> RECIEVE CRYPTO\n6 --> DELETE USER\n7 --> MENU\n8 --> EXIT\n")
	choice = int(input())

	if choice == 1:
		new_user()
	if choice == 2:
		usr = users()
		for i in usr:
			print(i,end=' ')
		print("\n")
	if choice == 3:
		balance()
	if choice == 4:
		send()
	if choice == 5:
		try:
			recieve()
		except:
			print("\nSERVER NOT FOUND... \n")
	if choice == 6:
		del_usr()
	if choice == 7:
		print("\nMENU")
		print("\033[1;32m \n1 --> ADD NEW USER\n2 --> LIST OF EXISTING USERS\n3 --> CHECK BALANCE\n4 --> SEND CRYPTO\n5 --> RECIEVE CRYPTO\n6 --> DELETE USER\n7 --> MENU\n8 --> EXIT\n")
	if choice == 8:
		print("EXITING...\nBYE")
		break
		exit()
	else:
		print("ENTER FROM THE GIVEN MENU")

