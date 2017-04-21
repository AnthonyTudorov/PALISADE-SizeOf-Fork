//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
6/17/2015 4:37AM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Gyana Sahu, grs22@njit.edu
Description:
This code exercises the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.
In this code we:
- Generate a key pair.
- Encrypt a string of data.
- Decrypt the data.
- Generate a new key pair.
- Generate a proxy re-encryption key.
- Re-Encrypt the encrypted data.
- Decrypt the re-encrypted data.
We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor and may be closer to AES-256.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <iostream>
#include <fstream>


#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"
#include <random>


using namespace std;
using namespace lbcrypto;


#include <iterator>

void LTVAutomorphismIntArray();

int main() {

	LTVAutomorphismIntArray();

	system("pause");
	return 0;
}

void LTVAutomorphismIntArray() {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	usint plaintextModulus = 64;

	float stdDev = 4;

	DiscreteGaussianGenerator dgg(stdDev);

	ILParams params(m, q, rootOfUnity);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(plaintextModulus, m, q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 0,1,2,3,4,5,6,7 };
	//PackedIntPlaintextEncoding intArray(vectorOfInts);
	IntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	std::cout << "about to run EvalAutomorphismGen" << std::endl;

	shared_ptr<std::vector<shared_ptr<LPEvalKey<ILVector2n>>>> evalKeys =
		cc.EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, 3);

	std::cout << "just ran EvalAutomorphismGen" << std::endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> permutedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1;

	std::cout << "about to run EvalAtIndex" << std::endl;

	p1 = cc.EvalAtIndex(ciphertext[0], 3, *evalKeys);

	std::cout << "just ran EvalAtIndex" << std::endl;

	permutedCiphertext.push_back(p1);

	//PackedIntPlaintextEncoding intArrayNew;
	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index 3 (using only odd coefficients)\n\t" << intArrayNew << std::endl;


}

