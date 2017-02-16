import pycrypto

crypto = pycrypto.Crypto()

def demo_crypto(plaintext):
	
	print 'Encrypting: ' + repr(plaintext)
	ciphertext = crypto.encrypt(plaintext)
	
	decrypted_text = crypto.decrypt(ciphertext)
	print 'Decrypted text: ' + repr(decrypted_text)
	
	print '*' * 20

#demo_crypto([0,1,0,1,0,1,0,1])

p1 = [1,2,3,4,5,6,7,8,9,10]
p2 = [5,6,7,8,9,10,11,12,13,14]

#p1pre = [1,2,3,4,5,6,7,8,9,10]
#p2pre = [5,6,7,8,9,10,11,12,13,14]

#p1 = [0] * 20
#p2 = [0] * 20

#p1[1::2] = p1pre
#p2[1::2] = p2pre

print "\nplaintext 1: " + repr(p1)
c1 = crypto.encrypt(p1)
print "\nplaintext 2: " + repr(p2)
c2 = crypto.encrypt(p2)

print "Demo of ciphertext serialization and deserialization"

serializedString = c1.serialize()
cDeserialized = pycrypto.Ciphertext()
cDeserialized.deserialize(serializedString)
p_deserialized = crypto.decrypt(cDeserialized)
print "Deserialzed decryptected text for plaintext 1: :" + repr(p_deserialized)

print "Demo of public key serialization and deserialization"

serializedString = crypto.serializePublicKey()
crypto.deserializePublicKey(serializedString)

print "Performed serialization and deserialization of the public key"

print "Demo of private key serialization and deserialization"

serializedString = crypto.serializePrivateKey()
crypto.deserializePrivateKey(serializedString)

print "Performed serialization and deserialization of the private key"

print "Demo of eval key serialization and deserialization"

serializedString = crypto.serializeEvalKey(2)
crypto.deserializeEvalKey(serializedString,2)

print "Performed serialization and deserialization of an eval key"

c1i3 = crypto.evalAtIndex(c1,3)
c1i6 = crypto.evalAtIndex(c1,6)
c1_plus = crypto.evalAdd(c1, c1i3)
c2_plus = crypto.evalAdd(c1_plus, c1i6)

p1_plus = crypto.decrypt(c2_plus)

print "\nSum of elements at index 1, 3, and 6 = " + str(p1_plus[0])

c2i3 = crypto.evalAtIndex(c2,3)
c3_plus = crypto.evalAdd(c2_plus, c2i3)
p2_plus = crypto.decrypt(c3_plus)

print "\nSum of ptxt1 elements at index 1, 3, and 6 and ptxt2 at index 3 = " + str(p2_plus[0])

c_plus = crypto.evalAdd(c1, c2)
p_plus = crypto.decrypt(c_plus)
print '%s + %s = %s' % (repr(p1), repr(p2), repr(p_plus))
