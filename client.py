import socket,json
import time
import Crypto.Util.number
import Crypto.Random
import sys

print("#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||#")
print()
print("                                         Elliptical Curve Cryptography                                      ")
def findModularInverse(a, mod): #modular inverse of number
			
	while(a < 0):
		a = a + mod
	
	x1 = 1; x2 = 0; x3 = mod
	y1 = 0; y2 = 1; y3 = a
	q = int(x3 / y3)
	t1 = x1 - q*y1
	t2 = x2 - q*y2
	t3 = x3 - (q*y3)
	
	while(y3 != 1):
		x1 = y1; x2 = y2; x3 = y3
		y1 = t1; y2 = t2; y3 = t3
		q = int(x3 / y3)
		t1 = x1 - q*y1
		t2 = x2 - q*y2
		t3 = x3 - (q*y3)
	
	while(y2 < 0):
		y2 = y2 + mod
	return y2

def pointAddition(x1, y1, x2, y2, a, b, mod): #addition of ECC points

	#finding lambdaa value
	if x1 == x2 and y1 == y2:
		lambdaa = (3*x1*x1 + a) * (findModularInverse(2*y1, mod))
	else:
		lambdaa = (y2 - y1)*(findModularInverse((x2 - x1), mod))

	#finding addition result point
	x3 = lambdaa*lambdaa - x1 - x2
	y3 = lambdaa*(x1 - x3) - y1
	x3 = x3 % mod
	y3 = y3 % mod

	while(x3 < 0):
		x3 = x3 + mod
	
	while(y3 < 0):
		y3 = y3 + mod
	
	return x3, y3

def applyDoubleAndAddMethod(x0, y0, k, a, b, mod): #doubling and adding point for multiplication
	
	x_temp = x0
	y_temp = y0
	
	kAsBinary = bin(k) #converting 128-bit key to binary bits 
	for i in range(0, len(kAsBinary)):
		currentBit = kAsBinary[i: i+1]
		#ECC point doubling
		x_temp, y_temp = pointAddition(x_temp, y_temp, x_temp, y_temp, a, b, mod)
		if currentBit == '1':
			#ECC base point adding
			x_temp, y_temp = pointAddition(x_temp, y_temp, x0, y0, a, b, mod)
	
	return x_temp, y_temp
#|||||||||||||||||||||||||||||||||||||||||||||||||||||||#

#network connection server side
print()
print("                  ************************Requesting for Connection***********************                   ")
print()
#server name and port name
host = 'local host'
port = 5004
  
#socket creation at client side
s = socket.socket(socket.AF_INET,
                  socket.SOCK_STREAM)
  
# connecting with server and port
s.connect(('127.0.0.1', port))
print("Connected with Server!!!")
print()

print("                 ***********************Generating Priv/Pub Key Pair************************                 ")
print()
#prime feild value over which curve is defined
mod=295295436298121533964386134622010970389
a =0
b =-4
#base point/generator on ECC curve
base_point = [ 254052425592017427463487664867333612901 ,  265524280608103560115086963712418825087]
#print("Base point: (",base_point[0],", ",base_point[1],")")

#randomly selected secret key
secretKey = Crypto.Util.number.getPrime(128, randfunc=Crypto.Random.get_random_bytes)
#public key generation from secret key and base point multiplication
publicKey = applyDoubleAndAddMethod(base_point[0], base_point[1], secretKey, a, b, mod)
print("Client Public Key",publicKey) 
print()
print("               *****************************Public Key Sharing*****************************                 ")
print()
#receiving server public key
data = s.recv(1024)
data = json.loads(data.decode())
serverKey = data.get("a")
print('Received Server Public Key:',serverKey)
#send public to the server
data = json.dumps({"a": publicKey})
s.send(data.encode())
lst = []
print()
plaintext=input("Enter Message : ")
#encoding message to int for the plaintext coordinate
encoded_text = plaintext.encode('utf-8')
hex_text = encoded_text.hex()
int_text = int(hex_text, 16)
#x coordinate is message ascii and y coordinate rondomly selected
lst=[int_text,Crypto.Util.number.getPrime(128, randfunc=Crypto.Random.get_random_bytes)]
     
print("Plaintext coordinates:",lst)
print()
print("               ************************Encrypting and sending Message**********************                ")
print()
#random key selected
randomKey = 3#Crypto.Util.number.getPrime(128, randfunc=Crypto.Random.get_random_bytes)
#first cipher by mulitplying base point with random key
c1 = applyDoubleAndAddMethod(base_point[0], base_point[1], randomKey, a, b, mod)
#(sever publickey * random key)+c2
c2 = applyDoubleAndAddMethod(serverKey[0], serverKey[1], randomKey, a, b, mod)
c2 = pointAddition(c2[0], c2[1], lst[0], lst[1], a, b, mod)

print("ciphertext")
print("c1: ", c1)
print("c2: ", c2)
data = json.dumps({"a": c1, "b": c2})
s.send(data.encode())
print()
print("#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||#")
print()
# disconnect the client
s.close()
