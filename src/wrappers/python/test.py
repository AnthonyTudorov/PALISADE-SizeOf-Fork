import pycrypto

obfuscator = pycrypto.Obfuscator()

obfPattern = "1?0"

obfuscator.Initialize(obfPattern,8,1)

print ("Pattern to be obfuscated: " + obfPattern)

print "Obfuscation completed."

testpattern1 = "110"
testpattern2 = "010"

result1 = obfuscator.EvaluateClear(testpattern1)

print(' Result of cleartext evaluaton of ' + repr(testpattern1) + ' is ' + repr(result1))

result2 = obfuscator.EvaluateClear(testpattern2)

print(' Result of cleartext evaluaton of ' + repr(testpattern2) + ' is ' + repr(result2))

result3 = obfuscator.Evaluate(testpattern1)

print(' Result of obfuscated evaluaton of ' + repr(testpattern1) + ' is ' + repr(result3))

result4 = obfuscator.Evaluate(testpattern2)

print(' Result of obfuscated evaluaton of ' + repr(testpattern2) + ' is ' + repr(result4))

