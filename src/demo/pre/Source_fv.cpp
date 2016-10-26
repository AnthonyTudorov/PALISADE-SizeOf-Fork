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

#include "../../lib/palisade.h"
#include "../../lib/palisadespace.h"

#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/encoding/intplaintextencoding.h"

#include "../../lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;
void EvalMul(int input, MODE mode);
//double currentDateTime();


#include <iterator>

int main() {

	std::cout << "Relinearization window : " << std::endl;
	std::cout << "0 (r = 1), 1 (r = 2), 2 (r = 4), 3 (r = 8), 4 (r = 16): [0] ";

	int input = 0;
	std::cin >> input;
	//cleans up the buffer
	cin.ignore();

	if ((input<0) || (input>4))
		input = 0;

	cout << "\nStarting FV Eval Mult demo in the RLWE mode" << endl;

	EvalMul(input, RLWE);

	cout << "\nStarting FV Eval Mult demo in the OPTIMIZED mode" << endl;

	EvalMul(input, OPTIMIZED);
	
	std::cout << "Execution Completed. Press any key to continue." << std::endl;

	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}

void EvalMul(int input, MODE mode) {

	int relinWindows[] = { 1, 2, 4, 8, 16 };

	usint relWindow = relinWindows[input];

	BigBinaryInteger plaintextModulus(BigBinaryInteger("4"));
	float stdDev = 4;

	//Set crypto parametes
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
			4, 0, "0", "0",
			relWindow, stdDev, "0", mode, "0", "0", 0, 9, 1.006);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	double diff, start, finish;

	start = currentDateTime();

	cc.GetEncryptionAlgorithm().ParamsGen(cc.GetCryptoParameters(), 0, 1);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Parameter generation time: " << "\t" << diff << " ms" << endl;

	std::cout << "n = " << cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cc.GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc.KeyGen();

	if( !kp.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2, true);

	start = currentDateTime();

	ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1, true);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Encryption execution time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	shared_ptr<LPEvalKey<ILVector2n>> evalKey;

	//generate the evaluate key
	evalKey = cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextMult;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempMult;

	start = currentDateTime();

	ciphertextTempMult = cc.EvalMult(ciphertext1[0], ciphertext2[0], evalKey);

	finish = currentDateTime();
	diff = finish - start;

	cout << "EvalMult execution time: " << "\t" << diff << " ms" << endl;

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult, true);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Decryption execution time: " << "\t" << diff << " ms" << endl;

	plaintextNewMult.resize(plaintextMult.size());

	cout << plaintext1 << " * " << plaintext2 << " = \n" << plaintextNewMult << endl;

	cout << "Correct answer: = " << plaintextMult << endl;

	string test;

	if (plaintextNewMult == plaintextMult)
		test = "SUCCESS";
	else
		test = "FAILURE";

	cout << "Result: " << test << endl;

	//TernaryUniformGenerator tug;

	//cout << tug.GenerateVector(10, BigBinaryInteger("17")) << endl;

}
