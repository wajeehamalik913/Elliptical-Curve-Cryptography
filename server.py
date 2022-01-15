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
print("                  ************************Listening for Connection***********************                   ")
print()
#server name and port name
host = 'local host'
port = 5004
  
#socket creation at server side
s = socket.socket(socket.AF_INET,
                  socket.SOCK_STREAM)
  
# binding socket with server and port
s.bind(('', port))
  
# listening for client connection
s.listen(1)
  
# wait for client to accept
c, addr = s.accept()
  
# display client address
print("Connected with:", str(addr))

print()

print("                ***********************Generating Priv/Pub Key Pair************************                 ")
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
print("Server Public Key : ",publicKey)
print()
print("               *****************************Public Key Sharing*****************************                 ")

#send public to the client 
data = json.dumps({"a": publicKey})
c.send(data.encode())
print()
#receiving client public key
data = c.recv(1024)
data = json.loads(data.decode())
Recieved = data.get("a")
print('Recieved Client Public Key: ', Recieved)
print()
print("               **************************Recieving Encrypted Message************************                ")
print()
#recieving message in encrypted cipher text
ciphers=c.recv(1024)
ciphers=json.loads(ciphers.decode())
c1=ciphers.get("a")
c2=ciphers.get("b")
print("\nciphertext")
print("c1: ", c1)
print("c2: ", c2)

print()
print("               *******************************Decrypting Message****************************                ")
print()
#-secret key multiplication with c1
dx, dy = applyDoubleAndAddMethod(c1[0], c1[1], secretKey, a, b, mod)
dy = dy * -1 #curve is symmetric about x-axis. in this way, inverse point found

#c2 + secret key * (-c1)
decrypted = pointAddition(c2[0], c2[1], dx, dy, a, b, mod)

print("decrypted coordinates: ",decrypted)
#converting coordinates to text message
import codecs
hex_text = hex(decrypted[0])
hex_text = hex_text[2:] #remove 0x
decryptext=codecs.decode(codecs.decode(hex_text,'hex'),'ascii')
print("decrypted message: ",decryptext)
print()
print("#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||#")
print()
# disconnect the server
c.close()
