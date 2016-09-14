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

#include "../../lib/math/nbtheory.h"
#include "../../lib/math/distrgen.h"

#include "../../lib/lattice/ilvector2n.h"
#include "../../lib/lattice/ilvectorarray2n.h"
#include "../../lib/crypto/cryptocontext.h"

#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/cryptoutility.h"
#include "time.h"

#include <chrono>
#include "../../lib/utils/debug.h"
#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/encoding/intplaintextencoding.h"

#include "testJson.h"
#include "testJson.cpp"

using namespace std;
using namespace lbcrypto;


void BenchMarking();
void BenchMarking_DCRT_ByteArray();

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

#include <iterator>
int main() {
	
	BenchMarking_DCRT_ByteArray();

	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}

void BenchMarking_DCRT_ByteArray(){
	double diff, start, finish;
	std::map<usint, std::vector<double>> encryptTimer;
	std::map<usint, std::vector<double>> decryptTimer;

//	usint m = 16;
	usint numberOfIterations = 3;
	usint numberOfTowers = 20;


	std::vector<BytePlaintextEncoding> plaintextEncodingVector;
	std:map<usint, BytePlaintextEncoding> cyclotomicOrderToByteArrayMapper;

	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16 ,BytePlaintextEncoding("A")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32, BytePlaintextEncoding("AB")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(64, BytePlaintextEncoding("ABCD")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(128, BytePlaintextEncoding("ABCDEFGH")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(256, BytePlaintextEncoding("ABCDEFGHIJKLMNOP")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(512, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(1024, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(2048, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(4096, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(8192, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16384, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32768, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));

	for (usint m = 16; m <= 64; m = m * 2) {

		std::vector<double> encryptTimeTower(20);
		std::fill(encryptTimeTower.begin(), encryptTimeTower.end(), 0);
		encryptTimer.insert(std::make_pair(m, encryptTimeTower));

		std::vector<double> decryptTimeTower(20);
		std::fill(decryptTimeTower.begin(), decryptTimeTower.end(), 0);
		decryptTimer.insert(std::make_pair(m, decryptTimeTower));

		for (usint k = 0; k < numberOfIterations; k++) {
			for (usint i = 1; i <= 3; i++) {
				float stdDev = 4;

				vector<BigBinaryInteger> moduli(i);

				vector<BigBinaryInteger> rootsOfUnity(i);

				BigBinaryInteger q("1");
				BigBinaryInteger temp;
				BigBinaryInteger modulus("1");

				for (int j = 0; j < i; j++) {
					lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
					moduli[j] = q;
					rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
					modulus = modulus* moduli[j];
				}

				DiscreteGaussianGenerator dgg(stdDev);

				ILDCRTParams params(m, moduli, rootsOfUnity);

				LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
				cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
				cryptoParams.SetDistributionParameter(stdDev);
				cryptoParams.SetRelinWindow(1);
				cryptoParams.SetElementParams(params);
				cryptoParams.SetDiscreteGaussianGenerator(dgg);

				Ciphertext<ILVectorArray2n> cipherText;
				cipherText.SetCryptoParameters(&cryptoParams);

				LPPublicKey<ILVectorArray2n> pk(cryptoParams);
				LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

				LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;
				algorithm.Enable(ENCRYPTION);
				algorithm.Enable(PRE);

				algorithm.KeyGen(&pk, &sk);

				vector<Ciphertext<ILVectorArray2n>> ciphertext;

				start = currentDateTime();

				CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, cyclotomicOrderToByteArrayMapper.at(m), &ciphertext);
				finish = currentDateTime();
				diff = finish - start;
				encryptTimer.at(m).at(i) += diff;

				BytePlaintextEncoding plaintextNew;

				start = currentDateTime();

				CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertext, &plaintextNew);
				finish = currentDateTime();
				diff = finish - start;
				decryptTimer.at(m).at(i) += diff;

				cout << plaintextNew << endl;

			}
		}
	}
	for (usint m = 16; m <= 64; m = m * 2) {
		cout << "m is :" << m << endl;
		for (int i = 1; i < 4; i++) {
			cout << "tower size:" << i << endl;
			cout << encryptTimer.at(m).at(i) / 3 << endl;
			cout << decryptTimer.at(m).at(i) / 3 << endl;
			cout << endl;
		}
	}
}

