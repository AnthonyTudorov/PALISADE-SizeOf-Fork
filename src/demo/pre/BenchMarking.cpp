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
#include <string>

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


void BenchMarking();
void BenchMarking_DCRT_ByteArray(bool intOrByteArray);
void BenchMarking_DCRT_Eval_Mult();
void BenchMarking_DCRT_Eval_Add();
void BenchMarking_Ring_Reduce_Single_Crt();
void BenchMarking_Encrypt_Single_Crt();
void BenchMarking_KeySwitch_Single_Crt();
void BenchMarking_Pre();
void Benchmarking_find_table_of_secure_params();
void PreComputeIntArray(usint minCycorder, usint maxCycorder, usint intArray_modulus);
bool checkSecureParams(const std::vector<BigBinaryInteger> &moduli, const usint towerSize, const usint ringDimension, std::map<double, std::map<usint, usint>> *deltaToRingdimensionToTowerSizeMapper, const std::vector<double> &deltas, BigBinaryInteger &multModuli);
std::string split(const std::string s, char c);
void standardMapTest();
void CalculateModuli(usint m);
int bitSizeCalculator(int n);
void ringReduceTest();
char getRandomChar();
/**
 * @brief Input parameters for PRE example.
 */
struct secureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};
static std::map<usint, std::map<usint, BigBinaryInteger>> moduli; //first usint is cyc order, second map maps towersize to moduli
static std::map<usint, std::map<usint, BigBinaryInteger>> rootsOfUnity; //first usint is cyc order, second map maps towersize to rootsOfUnity
static std::map<usint, std::map<usint, usint>> bitSizes; //first usint is cyc order, second map maps towersize to bitsize
static std::map<usint, IntPlaintextEncoding> cyclotomicOrderToIntArrayMapper; //used for encryption/decryption
static std::map<usint, BytePlaintextEncoding> cyclotomicOrderToByteArrayMapper; //used for encryption/decryption
static const char alphanum[] =
"0123456789"
"!@#$%^&*"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"; //to generate a random string

static int stringLength = sizeof(alphanum) - 1;
static usint maxCyclotomicOrder = 32;
static usint maxTowerSize = 20;
static usint numberOfIterations = 1;
static usint minCyclotomicOrder = 16;
static usint minTowerSize = 1;
static float stdDev = 4;
static int randSeed = 1;



#include <iterator>
int main() {
//	ringReduceTest();
	//	CalculateModuli();
	BenchMarking_DCRT_ByteArray(1);
	//BenchMarking_DCRT_ByteArray_KeySwitch();
	//BenchMarking_DCRT_Eval_Mult();
//	BenchMarking_DCRT_IntArray();
//	BenchMarking_Mod_Reduce();
//	BenchMarking_Ring_Reduce_Dcrt();
//	BenchMarking_Ring_Reduce_Single_Crt();
//	BenchMarking_Encrypt_Single_Crt();
//	BenchMarking_KeySwitch_Single_Crt();
//	BenchMarking_Pre();
//	Benchmarking_find_table_of_secure_params();
//	standardMapTest();
	
	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}

int bitSizeCalculator(int n) {
	if (n == -1) return 32;
	if (n == 0) return 1;
	int r = 0;
	while (n)
	{
		++r;
		n >>= 1;
	}
	return r;
}

char getRandomChar()  // Random string generator function.
{
	const usint seed = 2;
	srand(time(0) + randSeed++);
	return alphanum[rand() % stringLength];
}

void CalculateModuli(usint m) {

	double plaintextModulus = 2;
	double assuranceMeasureW = 6;
	double gaussianParameterR = 4;
	double q1;
	double q2;
	double sqrtn;
	double ringDimensionN;
	char c = '.';
	BigBinaryInteger temp;

//	for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {
		std::map<usint, BigBinaryInteger> towerToModuliOrRootOfUnity;
		moduli.insert(std::make_pair(m, towerToModuliOrRootOfUnity));
		rootsOfUnity.insert(std::make_pair(m, towerToModuliOrRootOfUnity));
		std::map<usint, usint> towerOrderToBitsMap;
		bitSizes.insert(std::make_pair(m, towerOrderToBitsMap));

		ringDimensionN = m / 2;
		sqrtn = sqrt(ringDimensionN);
		q1 = 4 * plaintextModulus * gaussianParameterR * sqrtn * assuranceMeasureW;
		q2 = 4 * pow(plaintextModulus, 2) * pow(gaussianParameterR, 5) * pow(sqrtn, 3) * pow(assuranceMeasureW, 5);

		BigBinaryInteger q1BBI(split(to_string(q1), c));
		BigBinaryInteger q2BBI(split(to_string(q2), c));

		lbcrypto::NextQ(q1BBI, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		lbcrypto::NextQ(q2BBI, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		cout << endl;
		for (usint i = 1; i <= maxTowerSize; i++) {
			std::vector<BigBinaryInteger> moduli_vector_local(i);
			if (i == 1) {
				moduli[m][i] = q1BBI;
				rootsOfUnity[m][i] = RootOfUnity(m, q1BBI);
				}
			else if (i == 2) {
				moduli[m][i] = q2BBI;
				rootsOfUnity[m][i] = RootOfUnity(m, q2BBI);
				}
			else {
				temp = moduli[m][i - 1];
				lbcrypto::NextQ(temp, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
				moduli[m][i] = temp;
				rootsOfUnity[m][i] = RootOfUnity(m, temp);
			}
			double doubleOfBBI = moduli[m][i].ConvertToDouble();
			double bitSize = floor(log(doubleOfBBI) / log(2)) + 1;
			bitSizes[m][i] = bitSize;
			if (i != 1) {
				std::vector<BigBinaryInteger> moduliV;
				moduliV.reserve(i-1);
				for (usint j = 1; j <= i; j++) {
					moduliV.push_back(moduli[m][j]);
				}
				ILVectorArray2n::PreComputeCRIFactors(moduliV,m);
			}
//		}
	}

	ofstream myfile;
	myfile.open("C:/Users/Ha/Documents/Code/Palisade/benchmark.csv", std::ios_base::app);
	myfile << "\n";
	myfile << "Bit size\n";
	myfile << "Cyclotomic Order,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768\n";

	for (usint i = minTowerSize; i <= maxTowerSize; i++) {
		myfile << "t=" << i << ",";
		for (usint cycOrder = minCyclotomicOrder; cycOrder <= maxCyclotomicOrder; cycOrder = cycOrder * 2) {
			myfile << bitSizes[cycOrder][i] << ",";
		}
		myfile << "\n";
	}
}

void PreComputeIntArray(usint minCycorder, usint maxCycorder, usint intArray_modulus) {
	cyclotomicOrderToIntArrayMapper.clear();
	for (usint m = minCycorder; m <= maxCyclotomicOrder; m = m * 2) {
		std::vector<uint32_t> randomValues;
		randomValues.reserve(m/2);
		for (usint i = 0; i < m/2; i++) {
			srand(time(0) + randSeed++);
			randomValues.push_back(rand() % intArray_modulus);
		}
		cyclotomicOrderToIntArrayMapper.insert(std::make_pair(m, randomValues));
	}
}

void PreComputeByteArray(usint minCycorder, usint maxCycorder) {
	cyclotomicOrderToByteArrayMapper.clear();
	for (usint m = minCycorder; m <= maxCyclotomicOrder; m = m * 2) {
		std::string x = "";
		for (usint i = 0; i < m / 2; i++) {
			x = x + getRandomChar();
		}
		cyclotomicOrderToByteArrayMapper.insert(std::make_pair(m, BytePlaintextEncoding(x)));
	}
}
//false for intArray true for ByteArray
void BenchMarking_DCRT_ByteArray(bool intOrByteArray){
	double diff, start, finish;
	std::map<usint, std::vector<double>> encryptTimer;
	std::map<usint, std::vector<double>> decryptTimer;
	std::map<usint, std::vector<double>> modReduceTimer;
	std::map<usint, std::vector<double>> ringReduceTimer;
	std::map<usint, std::vector<double>> keySwitchTimer;
	if (!intOrByteArray) {
		PreComputeIntArray(minCyclotomicOrder, maxCyclotomicOrder, 2);
	}
	else {
		PreComputeByteArray(minCyclotomicOrder, maxCyclotomicOrder);
	}

	for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {
		CalculateModuli(m); // calculate moduli and precompute CRI factors
		std::vector<double> tower_timer(maxTowerSize + 1);
		std::fill(tower_timer.begin(), tower_timer.end(), 0);

		encryptTimer.insert(std::make_pair(m, tower_timer));
		modReduceTimer.insert(std::make_pair(m, tower_timer));
		ringReduceTimer.insert(std::make_pair(m, tower_timer));
		keySwitchTimer.insert(std::make_pair(m, tower_timer));
		decryptTimer.insert(std::make_pair(m, tower_timer));

		for (usint k = 0; k < numberOfIterations; k++) {
			for (usint i = minTowerSize; i <= maxTowerSize; i++) {
				/***************************SETUP START**********************************/
				cout << "Processing cyclotomic order of " << m << " and tower size of " << i << " under " << k << "th iteration" << endl;

				vector<BigBinaryInteger> moduli_vector(i);

				vector<BigBinaryInteger> rootsOfUnity_vector(i);

				for (int j = 0; j < i; j++) {
					moduli_vector[j] = moduli[m][j+1];
					rootsOfUnity_vector[j] = rootsOfUnity[m][j+1];
				}

				DiscreteGaussianGenerator dgg(stdDev);

				shared_ptr<ILDCRTParams> params(new ILDCRTParams(m, moduli_vector, rootsOfUnity_vector));

				LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
				cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
				cryptoParams.SetDistributionParameter(stdDev);
				cryptoParams.SetRelinWindow(1);
				cryptoParams.SetElementParams(params);
				cryptoParams.SetDiscreteGaussianGenerator(dgg);

				CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
				cc.Enable(ENCRYPTION);
				cc.Enable(SHE);
				cc.Enable(LEVELEDSHE);

				LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

				/***************************SETUP END**********************************/

				/***************************ENCRYPTION START**********************************/

				start = currentDateTime();
				vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext;
				if (!intOrByteArray) {
					ciphertext = cc.Encrypt(kp.publicKey, cyclotomicOrderToIntArrayMapper.at(m), false);
				}
				else {
					cout << cyclotomicOrderToByteArrayMapper.at(m) << endl;
					ciphertext = cc.Encrypt(kp.publicKey, cyclotomicOrderToByteArrayMapper.at(m));
				}

				finish = currentDateTime();
				diff = finish - start;
				encryptTimer.at(m).at(i) += diff;

				/***************************ENCRYPTION END**********************************/
				/***************************DECRYPTION START**********************************/
				if (!intOrByteArray) {
					IntPlaintextEncoding plaintextNew;
					start = currentDateTime();

					cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

					cout << "Decrypt " << plaintextNew << endl;

					finish = currentDateTime();
					diff = finish - start;
					decryptTimer.at(m).at(i) += diff;
				}
				else {
					BytePlaintextEncoding plaintextNew;
					start = currentDateTime();

					cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

					cout << "Decrypt " << plaintextNew << endl;

					finish = currentDateTime();
					diff = finish - start;
					decryptTimer.at(m).at(i) += diff;
				}

				/***************************DECRYPTION END**********************************/
				/***************************KETSWITCH START**********************************/
				LPKeyPair<ILVectorArray2n> kp2 = cc.KeyGen();

				shared_ptr<LPEvalKey<ILVectorArray2n>> keySwitchHint;
				keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

				start = currentDateTime();

				shared_ptr<Ciphertext<ILVectorArray2n>> cipherTextKeySwitch = cc.KeySwitch(keySwitchHint, ciphertext.at(0));

				finish = currentDateTime();
				diff = finish - start;
				keySwitchTimer.at(m).at(i) += diff;
				vector<shared_ptr<Ciphertext<ILVectorArray2n>>> cipherTextVector(1);
				cipherTextVector.at(0) = cipherTextKeySwitch;

				if (!intOrByteArray) {
					IntPlaintextEncoding plaintextNew_keyswitch_int;
					cc.Decrypt(kp2.secretKey, cipherTextVector, &plaintextNew_keyswitch_int);
					cout << "KeySwitch " << plaintextNew_keyswitch_int << endl;
				}

				else {
					BytePlaintextEncoding plaintextNew_keyswitch_byte;
					cc.Decrypt(kp2.secretKey, cipherTextVector, &plaintextNew_keyswitch_byte);
					cout << "KeySwitch " << plaintextNew_keyswitch_byte << endl;
				}
				
				/***************************KETSWITCH END**********************************/
				/***************************MODREDUCE START**********************************/
				if (i > 1) {
					vector<shared_ptr<Ciphertext<ILVectorArray2n>>> cipherTextModReduce(ciphertext);
					start = currentDateTime();

					cipherTextModReduce = cc.ModReduce(cipherTextModReduce);

					finish = currentDateTime();
					diff = finish - start;
					modReduceTimer.at(m).at(i) += diff;

					LPKeyPair<ILVectorArray2n> kp_modreduce(kp);

					ILVectorArray2n sk3PrivateElement(kp_modreduce.secretKey->GetPrivateElement());
					sk3PrivateElement.DropElementAtIndex(sk3PrivateElement.GetNumOfElements() - 1);
					kp_modreduce.secretKey->SetPrivateElement(sk3PrivateElement);

					if (!intOrByteArray) {
						IntPlaintextEncoding plaintextNew_modreduce;
						cc.Decrypt(kp_modreduce.secretKey, cipherTextModReduce, &plaintextNew_modreduce, false);
						cout << "Mod Reduce " << plaintextNew_modreduce << endl;
					}
					else {
						BytePlaintextEncoding plaintextNew_modreduce;
						cc.Decrypt(kp_modreduce.secretKey, cipherTextModReduce, &plaintextNew_modreduce);
						cout << "Mod Reduce " << plaintextNew_modreduce << endl;
					}
				}
			    /***************************MODREDUCE END**********************************/

				/***************************RINGREDUCE START**********************************/
				if (m > 16) {
					start = currentDateTime();

					LPKeyPair<ILVectorArray2n> kp_rr = cc.KeyGen();
					vector<shared_ptr<Ciphertext<ILVectorArray2n>>> cipherTextRingReduce;
					if (!intOrByteArray) {
						cipherTextRingReduce = cc.Encrypt(kp_rr.publicKey, cyclotomicOrderToIntArrayMapper.at(m), false);
					}
					else {
						cipherTextRingReduce = cc.Encrypt(kp_rr.publicKey, cyclotomicOrderToByteArrayMapper.at(m));
					}
					LPKeyPair<ILVectorArray2n> kp_sparse = cc.SparseKeyGen();

					shared_ptr<LPEvalKey<ILVectorArray2n>> keySwitchHint_sparse = cc.KeySwitchGen(kp_rr.secretKey, kp_sparse.secretKey);

					cipherTextRingReduce = cc.RingReduce(cipherTextRingReduce, keySwitchHint_sparse);

					finish = currentDateTime();
					diff = finish - start;
					ringReduceTimer.at(m).at(i) += diff;

					if (!intOrByteArray) {
						ILVectorArray2n skSparseElement(kp_sparse.secretKey->GetPrivateElement());
						skSparseElement.SwitchFormat();
						skSparseElement.Decompose();
						skSparseElement.SwitchFormat();

						kp_sparse.secretKey->SetPrivateElement(skSparseElement);

						IntPlaintextEncoding plaintextNew_ringreduce;

						cc.Decrypt(kp_sparse.secretKey, cipherTextRingReduce, &plaintextNew_ringreduce, false);

						cout << "Ring Reduce " << plaintextNew_ringreduce << endl;
					}
				}
				/***************************RINGREDUCE END**********************************/
			}
		
		}
		ILVectorArray2n::DestroyPrecomputedCRIFactors();
	}
	
	ofstream myfile;
	myfile.open("C:/Users/Ha/Documents/Code/Palisade/benchmark.csv", std::ios_base::app);
	myfile << "\n";
	myfile << "Encrypt-Decrypt Double-CRT\n";
	myfile << "Cyclotomic Order";
	for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {
		myfile << "," << m;
	}
	myfile << "\nEncrypt\n";

	for (usint i = minTowerSize; i <= maxTowerSize; i++) {
		myfile << "t=" << i << ",";
		for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {
			myfile << encryptTimer.at(m).at(i)/numberOfIterations << ",";
		}
		myfile << "\n";
	}

	myfile << "\n";
	myfile << "Decrypt \n";
	for (usint i = minTowerSize; i <= maxTowerSize; i++) {
		myfile << "t=" << i << ",";
		for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {
			myfile << decryptTimer.at(m).at(i)/numberOfIterations << ",";
		}
		myfile << "\n";
	}
	myfile << "\n" << numberOfIterations << " iterations\n";


	myfile << "\n";
	myfile << "ModReduce \n";
	for (usint i = minTowerSize; i <= maxTowerSize; i++) {
		myfile << "t=" << i << ",";
		for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {
			myfile << modReduceTimer.at(m).at(i) / numberOfIterations << ",";
		}
		myfile << "\n";
	}
	myfile << "\n" << numberOfIterations << " iterations\n";

	myfile << "\n";
	myfile << "RingReduce \n";
	for (usint i = minTowerSize; i <= maxTowerSize; i++) {
		myfile << "t=" << i << ",";
		for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {
			myfile << modReduceTimer.at(m).at(i) / numberOfIterations << ",";
		}
		myfile << "\n";
	}
	myfile << "\n" << numberOfIterations << " iterations\n";
}

void BenchMarking_DCRT_Eval_Mult() {
	/*double diff, start, finish;
	std::map<usint, std::vector<double>> evalMultTimerMap;

	for (usint m = minCyclotomicOrder; m <= maxCyclotomicOrder; m = m * 2) {

		std::vector<double> evalMultTimer(20);
		std::fill(evalMultTimer.begin(), evalMultTimer.end(), 0);
		evalMultTimerMap.insert(std::make_pair(m, evalMultTimer));

		for (usint k = 0; k < numberOfIterations; k++) {
			for (usint i = minTowerSize; i <= maxTowerSize; i++) {
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
				ILVectorArray2n element1(dgg, params, Format::EVALUATION);
				ILVectorArray2n element2(dgg, params, Format::EVALUATION);

				LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
				cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
				cryptoParams.SetDistributionParameter(stdDev);
				cryptoParams.SetRelinWindow(1);
				cryptoParams.SetElementParams(params);
				cryptoParams.SetDiscreteGaussianGenerator(dgg);

				Ciphertext<ILVectorArray2n> cipherText1;
				cipherText1.SetCryptoParameters(&cryptoParams);
				cipherText1.SetElement(element1);
				
				Ciphertext<ILVectorArray2n> cipherText2;
				cipherText2.SetCryptoParameters(&cryptoParams);
				cipherText2.SetElement(element2);

				Ciphertext<ILVectorArray2n> results;
				results.SetCryptoParameters(&cryptoParams);

				LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;
		
				algorithm.Enable(SHE);

				start = currentDateTime();

				algorithm.EvalMult(cipherText1, cipherText2, &results);

				finish = currentDateTime();
				diff = finish - start;
				evalMultTimerMap.at(m).at(i) += diff;
			}
		}
	}
	ofstream myfile;
	myfile.open("C:/Users/Ha/Documents/Code/Palisade/benchmark.csv", std::ios_base::app);
	myfile << "\n";
	myfile << "EvalMult Double-CRT\n";
	myfile << "Cyclotomic Order,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768\n";

	for (usint i = 1; i <= numberOfTowers; i++) {
		myfile << "t=" << i << ",";
		for (usint m = 16; m <= maxCyclotomicOrder; m = m * 2) {
			myfile << evalMultTimerMap.at(m).at(i) / numberOfIterations << ",";
		}
		myfile << "\n";
	}

	myfile << "\n" << numberOfIterations << " iterations\n";*/
}
//
//void BenchMarking_DCRT_Eval_Add() {
//	double diff, start, finish;
//	std::map<usint, std::vector<double>> evalAddTimerMap;
//
//	usint numberOfIterations = 3;
//	usint numberOfTowers = 4;
//	usint maxCyclotomicOrder = 32768;
//
//	for (usint m = 16; m <= maxCyclotomicOrder; m = m * 2) {
//
//		std::vector<double> evalAddTimer(20);
//		std::fill(evalAddTimer.begin(), evalAddTimer.end(), 0);
//		evalAddTimerMap.insert(std::make_pair(m, evalAddTimer));
//
//		for (usint k = 0; k < numberOfIterations; k++) {
//			for (usint i = 1; i <= numberOfTowers; i++) {
//				float stdDev = 4;
//
//				vector<BigBinaryInteger> moduli(i);
//
//				vector<BigBinaryInteger> rootsOfUnity(i);
//
//				BigBinaryInteger q("1");
//				BigBinaryInteger temp;
//				BigBinaryInteger modulus("1");
//
//				for (int j = 0; j < i; j++) {
//					lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
//					moduli[j] = q;
//					rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
//					modulus = modulus* moduli[j];
//				}
//
//				DiscreteGaussianGenerator dgg(stdDev);
//
//				ILDCRTParams params(m, moduli, rootsOfUnity);
//				ILVectorArray2n element1(dgg, params, Format::EVALUATION);
//				ILVectorArray2n element2(dgg, params, Format::EVALUATION);
//
//				LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
//				cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
//				cryptoParams.SetDistributionParameter(stdDev);
//				cryptoParams.SetRelinWindow(1);
//				cryptoParams.SetElementParams(params);
//				cryptoParams.SetDiscreteGaussianGenerator(dgg);
//
//				Ciphertext<ILVectorArray2n> cipherText1;
//				cipherText1.SetCryptoParameters(&cryptoParams);
//				cipherText1.SetElement(element1);
//
//				Ciphertext<ILVectorArray2n> cipherText2;
//				cipherText2.SetCryptoParameters(&cryptoParams);
//				cipherText2.SetElement(element2);
//
//				Ciphertext<ILVectorArray2n> results;
//				results.SetCryptoParameters(&cryptoParams);
//
//				LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;
//
//				algorithm.Enable(SHE);
//
//				start = currentDateTime();
//
//				algorithm.EvalAdd(cipherText1, cipherText2, &results);
//
//				finish = currentDateTime();
//				diff = finish - start;
//				evalAddTimerMap.at(m).at(i) += diff;
//			}
//		}
//	}
//	ofstream myfile;
//	myfile.open("C:/Users/Ha/Documents/Code/Palisade/benchmark.csv", std::ios_base::app);
//	myfile << "\n";
//	myfile << "EvalAdd Double-CRT\n";
//	myfile << "Cyclotomic Order,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768\n";
//
//	for (usint i = 1; i <= numberOfTowers; i++) {
//		myfile << "t=" << i << ",";
//		for (usint m = 16; m <= maxCyclotomicOrder; m = m * 2) {
//			myfile << evalAddTimerMap.at(m).at(i) / numberOfIterations << ",";
//		}
//		myfile << "\n";
//	}
//
//	myfile << "\n" << numberOfIterations << " iterations\n";
//}
//


//void BenchMarking_Ring_Reduce_Single_Crt() {
//	double diff, start, finish;
//	std::map<usint, double> ring_reduce_timer;
//
//	usint numberOfIterations = 1;
//
//	std:map<usint, IntPlaintextEncoding> cyclotomicOrderToIntArrayMapper;
//
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(16, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(32, IntPlaintextEncoding({ 1 , 0 , 0, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(64, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(128, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(256, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(512, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(1024, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(2048, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//	cyclotomicOrderToIntArrayMapper.insert(std::make_pair(4096, IntPlaintextEncoding({ 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0,  1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0, 1 , 0 , 1, 0, 1, 1, 1, 0 })));
//
//
//	for (usint m = 16; m <= 64; m = m * 2) {
//		double temp = 0;
//		ring_reduce_timer.insert(std::make_pair(m, temp));
//
//		for (usint k = 0; k < numberOfIterations; k++) {
//			float stdDev = 4;
//
//			BigBinaryInteger q("1");
//			BigBinaryInteger temp;
//
//			lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
//
//			DiscreteGaussianGenerator dgg(stdDev);
//			BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
//			ILParams params(m, q, RootOfUnity(m, q));
//
//			//This code is run only when performing execution time measurements
//
//			//Precomputations for FTT
//			ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);
//
//			//Precomputations for DGG
//			ILVector2n::PreComputeDggSamples(dgg, params);
//
//			LPCryptoParametersLTV<ILVector2n> cryptoParams;
//			cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
//			cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
//			cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
//			cryptoParams.SetElementParams(params);                // Set the initialization parameters.
//			cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
//
//			Ciphertext<ILVector2n> cipherText;
//			cipherText.SetCryptoParameters(&cryptoParams);
//
//			LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
//
//			algorithm.Enable(LEVELEDSHE);
//			algorithm.Enable(ENCRYPTION);
//
//			//Initialize the public key containers.
//			LPPublicKey<ILVector2n> pk(cryptoParams);
//			LPPrivateKey<ILVector2n> sk(cryptoParams);
//
//			algorithm.KeyGen(&pk, &sk);
//			vector<Ciphertext<ILVector2n>> ciphertext;
//
//			IntPlaintextEncoding intArray(cyclotomicOrderToIntArrayMapper.at(m));
//
//			CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray, &ciphertext, false);
//
//			LPPublicKey<ILVector2n> pk2(cryptoParams);
//			LPPrivateKey<ILVector2n> skSparse(cryptoParams);
//
//			algorithm.SparseKeyGen(&pk2, &skSparse);
//
//			LPEvalKeyNTRU<ILVector2n> keySwitchHint(cryptoParams);
//			algorithm.EvalMultKeyGen(sk, skSparse, &keySwitchHint);
//
//			vector<Ciphertext<ILVector2n>> newCiphertext;
//			newCiphertext.reserve(ciphertext.size());
//
//			CryptoUtility<ILVector2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &newCiphertext);
//
//			IntPlaintextEncoding intArrayNew;
//
//			start = currentDateTime();
//
//			CryptoUtility<ILVector2n>::RingReduce(algorithm, &ciphertext, keySwitchHint);
//
//			finish = currentDateTime();
//			diff = finish - start;
//			ring_reduce_timer.at(m) += diff;
//
//			ILVector2n skSparseElement(skSparse.GetPrivateElement());
//			skSparseElement.SwitchFormat();
//			skSparseElement.Decompose();
//			skSparseElement.SwitchFormat();
//
//			skSparse.SetPrivateElement(skSparseElement);
//
//			IntPlaintextEncoding intArrayNewRR;
//
//			LPCryptoParametersLTV<ILVector2n> cryptoParamsRR;
//			ILParams ilparams2(ciphertext[0].GetElement().GetParams().GetCyclotomicOrder() / 2, ciphertext[0].GetElement().GetParams().GetModulus(), ciphertext[0].GetElement().GetParams().GetRootOfUnity());
//			cryptoParamsRR.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
//			cryptoParamsRR.SetDistributionParameter(stdDev);          // Set the noise parameters.
//			cryptoParamsRR.SetRelinWindow(1);						   // Set the relinearization window
//			cryptoParamsRR.SetElementParams(ilparams2);                // Set the initialization parameters.
//			cryptoParamsRR.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
//
//		//	skSparse.SetCryptoParameters(&cryptoParamsRR);
//		}
//		ILVector2n::DestroyPreComputedSamples();
//	}
//	
//	for (usint m = 32; m <= 64; m = m * 2) {
//			cout << "m is :" << m << endl;
//			cout << ring_reduce_timer.at(m) / numberOfIterations << endl;
//			cout << endl;
//	}
//}
//

//void BenchMarking_Pre(){
//	double diff, start, finish;
//	std::map<usint, double> reEncryptTimer;
//
//	usint numberOfIterations = 3;
//
//	std::vector<BytePlaintextEncoding> plaintextEncodingVector;
//	std:map<usint, BytePlaintextEncoding> cyclotomicOrderToByteArrayMapper;
//
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16, BytePlaintextEncoding("A")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32, BytePlaintextEncoding("AB")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(64, BytePlaintextEncoding("ABCD")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(128, BytePlaintextEncoding("ABCDEFGH")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(256, BytePlaintextEncoding("ABCDEFGHIJKLMNOP")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(512, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(1024, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(2048, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(4096, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(8192, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16384, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32768, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//
//	for (usint m = 16; m <= 64; m = m * 2) {
//
//		double temp = 0;
//		reEncryptTimer.insert(std::make_pair(m, temp));
//
//		for (usint k = 0; k < numberOfIterations; k++) {
//			float stdDev = 4;
//
//			BigBinaryInteger q("1");
//			BigBinaryInteger temp;
//
//			lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
//
//			DiscreteGaussianGenerator dgg(stdDev);
//			BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
//			ILParams params(m, q, RootOfUnity(m, q));
//
//			//This code is run only when performing execution time measurements
//
//			//Precomputations for FTT
//			ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);
//
//			//Precomputations for DGG
//			ILVector2n::PreComputeDggSamples(dgg, params);
//
//			LPCryptoParametersLTV<ILVector2n> cryptoParams;
//			cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
//			cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
//			cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
//			cryptoParams.SetElementParams(params);                // Set the initialization parameters.
//			cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
//
//			Ciphertext<ILVector2n> cipherText;
//			cipherText.SetCryptoParameters(&cryptoParams);
//
//			LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
//			LPPublicKey<ILVector2n> pk(cryptoParams);
//			LPPrivateKey<ILVector2n> sk(cryptoParams);
//
//			algorithm.Enable(ENCRYPTION);
//			algorithm.Enable(PRE);
//
//			algorithm.KeyGen(&pk, &sk);
//
//			vector<Ciphertext<ILVector2n>> ciphertext;
//
//			start = currentDateTime();
//
//			CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, cyclotomicOrderToByteArrayMapper.at(m), &ciphertext);
//
//			LPPublicKey<ILVector2n> newPK(cryptoParams);
//			LPPrivateKey<ILVector2n> newSK(cryptoParams);
//
//			algorithm.KeyGen(&newPK, &newSK);	// This is the same core key generation operation.
//
//			LPEvalKeyNTRURelin<ILVector2n> evalKey(cryptoParams);
//
//			algorithm.ReKeyGen(newPK, sk, &evalKey);  // This is the core re-encryption operation.
//
//			vector<Ciphertext<ILVector2n>> newCiphertext;
//
//			start = currentDateTime();
//
//			CryptoUtility<ILVector2n>::ReEncrypt(algorithm, evalKey, ciphertext, &newCiphertext);  // This is the core re-encryption operation.
//
//			finish = currentDateTime();
//			diff = finish - start;
//			reEncryptTimer.at(m) += diff;
//
//			BytePlaintextEncoding plaintextNew;
//
//			CryptoUtility<ILVector2n>::Decrypt(algorithm, newSK, newCiphertext, &plaintextNew);  // This is the core decryption operation.
//
//			cout << plaintextNew << endl;
//
//		}
//		ILVector2n::DestroyPreComputedSamples();
//	}
//
//	for (usint m = 16; m <= 64; m = m * 2) {
//		cout << "m is :" << m << endl;
//		cout << reEncryptTimer.at(m) / numberOfIterations << endl;
//	}	cout << endl;
//}
//
//void BenchMarking_ComposedEvalMult(){}
//void BenchMarking_KeySwitch_Single_Crt(){
//	double diff, start, finish;
//	std::map<usint, double> keySwitchTimer;
//
//	usint numberOfIterations = 3;
//	usint numberOfTowers = 20;
//
//	std::vector<BytePlaintextEncoding> plaintextEncodingVector;
//    std:map<usint, BytePlaintextEncoding> cyclotomicOrderToByteArrayMapper;
//
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16, BytePlaintextEncoding("A")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32, BytePlaintextEncoding("AB")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(64, BytePlaintextEncoding("ABCD")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(128, BytePlaintextEncoding("ABCDEFGH")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(256, BytePlaintextEncoding("ABCDEFGHIJKLMNOP")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(512, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(1024, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(2048, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(4096, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(8192, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16384, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32768, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//
//	for (usint m = 16; m <= 64; m = m * 2) {
//
//		double temp = 0;
//		keySwitchTimer.insert(std::make_pair(m, temp));
//
//		for (usint k = 0; k < numberOfIterations; k++) {
//			float stdDev = 4;
//
//			BigBinaryInteger q("1");
//			BigBinaryInteger temp;
//
//			lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("10"), BigBinaryInteger("10"));
//
//			DiscreteGaussianGenerator dgg(stdDev);
//			BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
//			ILParams params(m, q, RootOfUnity(m, q));
//
//			//This code is run only when performing execution time measurements
//
//			//Precomputations for FTT
//			ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);
//
//			//Precomputations for DGG
//			ILVector2n::PreComputeDggSamples(dgg, params);
//
//			LPCryptoParametersLTV<ILVector2n> cryptoParams;
//			cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
//			cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
//			cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
//			cryptoParams.SetElementParams(params);                // Set the initialization parameters.
//			cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
//
//			Ciphertext<ILVector2n> cipherText;
//			cipherText.SetCryptoParameters(&cryptoParams);
//
//			LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
//			LPPublicKey<ILVector2n> pk(cryptoParams);
//			LPPrivateKey<ILVector2n> sk(cryptoParams);
//
//			algorithm.Enable(ENCRYPTION);
//			algorithm.Enable(LEVELEDSHE);
//
//			algorithm.KeyGen(&pk, &sk);
//
//			vector<Ciphertext<ILVector2n>> ciphertext;
//
//			start = currentDateTime();
//
//			CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, cyclotomicOrderToByteArrayMapper.at(m), &ciphertext);
//
//			LPPublicKey<ILVector2n> pkNew(cryptoParams);
//			LPPrivateKey<ILVector2n> skNew(cryptoParams);
//
//			algorithm.KeyGen(&pkNew, &skNew);
//
//			finish = currentDateTime();
//			diff = finish - start;
//			keySwitchTimer.at(m) += diff;
//
//			start = currentDateTime();
//
//			vector<Ciphertext<ILVector2n>> keySwitchedCiphertext;
//
//			LPEvalKeyNTRU<ILVector2n> keySwitchHint(cryptoParams);
//			algorithm.EvalMultKeyGen(sk, skNew, &keySwitchHint);
//
//			start = currentDateTime();
//
//			CryptoUtility<ILVector2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &keySwitchedCiphertext);
//
//			finish = currentDateTime();
//			diff = finish - start;
//			keySwitchTimer.at(m) += diff;
//
//			BytePlaintextEncoding plaintextNew;
//
//			CryptoUtility<ILVector2n>::Decrypt(algorithm, skNew, keySwitchedCiphertext, &plaintextNew);
//
//			cout << plaintextNew << endl;
//
//		}
//	}
//
//	for (usint m = 16; m <= 64; m = m * 2) {
//		cout << "m is :" << m << endl;
//		cout << keySwitchTimer.at(m) / numberOfIterations << endl;
//	}	cout << endl;
//}
//
//void BenchMarking_Encrypt_Single_Crt() {
//	double diff, start, finish;
//	std::map<usint, double> encryptTimer;
//	std::map<usint, double> decryptTimer;
//
//	usint numberOfIterations = 100;
//
//	std::vector<BytePlaintextEncoding> plaintextEncodingVector;
//	std:map<usint, BytePlaintextEncoding> cyclotomicOrderToByteArrayMapper;
//
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16, BytePlaintextEncoding("A")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32, BytePlaintextEncoding("AB")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(64, BytePlaintextEncoding("ABCD")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(128, BytePlaintextEncoding("ABCDEFGH")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(256, BytePlaintextEncoding("ABCDEFGHIJKLMNOP")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(512, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(1024, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(2048, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(4096, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(8192, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(16384, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//	cyclotomicOrderToByteArrayMapper.insert(std::make_pair(32768, BytePlaintextEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")));
//
//	for (usint m = 16; m <= 32768; m = m * 2) {
//
//		double temp = 0;
//		encryptTimer.insert(std::make_pair(m, temp));
//		decryptTimer.insert(std::make_pair(m, temp));
//
//		for (usint k = 0; k < numberOfIterations; k++) {
//			float stdDev = 4;
//
//			BigBinaryInteger q("1");
//			BigBinaryInteger temp;
//
//			lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
//
//			DiscreteGaussianGenerator dgg(stdDev);
//			BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
//			ILParams params(m, q, RootOfUnity(m, q));
//
//			//This code is run only when performing execution time measurements
//
//			//Precomputations for FTT
//			ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);
//
//			//Precomputations for DGG
//			ILVector2n::PreComputeDggSamples(dgg, params);
//
//			LPCryptoParametersLTV<ILVector2n> cryptoParams;
//			cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
//			cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
//			cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
//			cryptoParams.SetElementParams(params);                // Set the initialization parameters.
//			cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
//
//			Ciphertext<ILVector2n> cipherText;
//			cipherText.SetCryptoParameters(&cryptoParams);
//
//			LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
//			LPPublicKey<ILVector2n> pk(cryptoParams);
//			LPPrivateKey<ILVector2n> sk(cryptoParams);
//
//			algorithm.Enable(ENCRYPTION);
//
//			algorithm.KeyGen(&pk, &sk);
//
//			vector<Ciphertext<ILVector2n>> ciphertext;
//
//			start = currentDateTime();
//
//			CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, cyclotomicOrderToByteArrayMapper.at(m), &ciphertext);
//			
//			finish = currentDateTime();
//			diff = finish - start;
//			encryptTimer.at(m) += diff;
//
//			BytePlaintextEncoding plaintextNew;
//
//			start = currentDateTime();
//
//			CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext, &plaintextNew);
//			finish = currentDateTime();
//			diff = finish - start;
//			decryptTimer.at(m) += diff;
//		}
//	}
//
//	ofstream myfile;
//	myfile.open("C:/Users/Ha/Documents/Code/Palisade/benchmark.csv", std::ios_base::app);
//	myfile << "\n";
//	myfile << "Encrypt-Decrypt Single-CRT\n";
//	myfile << "Cyclotomic Order,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768\n";
//	myfile << "Encrypt,";
//
//	for(usint m = 16; m <= 32768; m = m * 2) {
//			myfile << encryptTimer.at(m)/ numberOfIterations << ",";
//		}	
//	myfile << "\n";
//	myfile << "Decrypt,";
//	for (usint m = 16; m <= 32768; m = m * 2) {
//		myfile << decryptTimer.at(m) / numberOfIterations << ",";
//	}
//	myfile << "\n" << numberOfIterations << " iterations\n";
//}
//
//void Benchmarking_find_table_of_secure_params() {
//	
//	double plaintextModulus = 2;
//	double assuranceMeasureW = 6;
//	double gaussianParameterR = 4;
//	std::map<double, std::map<usint, usint>> deltaToRingdimensiontoTowersizeMapper;// delta to (ringdimension to towersize) mapper
//	std::vector<double> deltas;
//	deltas.reserve(1);
//	deltas.push_back(1.007);
////	deltas.push_back(1.006);
//
//	std::map<usint, usint> ringDimensionToTowersizeMapper;
//
//	for (usint i = 0; i < deltas.size(); i++) {
//		deltaToRingdimensiontoTowersizeMapper.insert(std::make_pair(deltas.at(i), ringDimensionToTowersizeMapper));
//	}
//
//	double q1;
//	double q2;
//	double sqrtn;
//	double ringDimensionN;
//	BigBinaryInteger temp;
//	usint maxTowerSize = 9;
//	usint maxM = 32768;
//	char c = '.';
//
//		for (usint m = 2048; m <= maxM; m = m * 2) {
//			std::vector<BigBinaryInteger> moduli;
//			ringDimensionN = m / 2;
//			sqrtn = sqrt(ringDimensionN);
//			q1 = 4 * plaintextModulus * gaussianParameterR * sqrtn * assuranceMeasureW;
//			q2 = 4 * pow(plaintextModulus, 2) * pow(gaussianParameterR, 5) * pow(sqrtn, 3) * pow(assuranceMeasureW, 5);
//		
//			BigBinaryInteger q1Big(split(to_string(q1), c));
//			BigBinaryInteger q2Big(split(to_string(q2), c));
//			
//			lbcrypto::NextQ(q1Big, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
//			lbcrypto::NextQ(q2Big, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
//			
//			moduli.push_back(BigBinaryInteger::ZERO);
//			moduli.push_back(q1Big);
//			moduli.push_back(q2Big);
//			moduli.reserve(maxTowerSize + 1);
//			BigBinaryInteger modulusMult(q1Big);
//
//			for (usint towerSize = 1; towerSize <= maxTowerSize; towerSize++) {
//				if (towerSize != 1 && towerSize != 2) {
//					temp = moduli[towerSize - 1];
//					lbcrypto::NextQ(temp, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
//					moduli[towerSize] = temp;
//					modulusMult = modulusMult * temp;
//					
//				}
//
//				else if(towerSize == 2){
//					modulusMult = modulusMult * BigBinaryInteger(q2Big);
//				}
//				checkSecureParams(moduli, towerSize, ringDimensionN, &deltaToRingdimensiontoTowersizeMapper, deltas, modulusMult);
//
//			}
//	}
//		for (usint i = 0; i < deltas.size();i++ ) {
//			
//			cout << "Printing delta " << deltas.at(i)<< endl;
//			std::map<usint, usint> deltaVector = deltaToRingdimensiontoTowersizeMapper.at(deltas.at(i));
//			
//			map<usint, usint>::iterator it;
//			for (it = deltaVector.begin(); it != deltaVector.end(); it++)
//			{
//				std::cout << it->first << ':' << it->second << std::endl;
//			}
//		}
//}

bool checkSecureParams(const std::vector<BigBinaryInteger> &moduli, const usint towerSize, const usint ringDimension, std::map<double, std::map<usint, usint>> *deltaToRingdimensionToTowerSizeMapper, const std::vector<double> &deltas, BigBinaryInteger &multModuli) {
	double modulusMultDouble = multModuli.ConvertToDouble();
	double logOfModulusMult = log(modulusMultDouble) / log(2);

	for (usint i = 0; i < deltas.size(); i++) {
		double logDelta = 4 * (log(deltas.at(i)) / log(2));
		double securityFactorCheck = logOfModulusMult / logDelta;
		if ((ringDimension-securityFactorCheck) > 0.0001) {
			(*deltaToRingdimensionToTowerSizeMapper)[deltas.at(i)][ringDimension] = towerSize;
		}
	}
}

std::string split(const std::string s, char c) {
	std::string result;
	const char *str = s.c_str();
	const char *begin = str;
	while (*str != c && *str)
		str++;
	result = std::string(begin, str);
	return result;
}

void standardMapTest() {
	std::map<double, std::map<usint, usint>> deltaToRingdimensionToTowerSizeMapper;
	usint a = 1;
	usint b = 2;

	std::map<usint, usint> aToX;
	std::map<usint, usint> bToX;

	deltaToRingdimensionToTowerSizeMapper.insert(std::make_pair(a, aToX));
	deltaToRingdimensionToTowerSizeMapper.insert(std::make_pair(b, bToX));

	deltaToRingdimensionToTowerSizeMapper[a].insert(std::make_pair(a, 0));
	deltaToRingdimensionToTowerSizeMapper[a].insert(std::make_pair(a+1, 1));
	deltaToRingdimensionToTowerSizeMapper[a].insert(std::make_pair(a+2, 2));


	deltaToRingdimensionToTowerSizeMapper[b].insert(std::make_pair(b, 0));
	deltaToRingdimensionToTowerSizeMapper[b].insert(std::make_pair(b + 1, 1));
	deltaToRingdimensionToTowerSizeMapper[b].insert(std::make_pair(b + 2, 2));

	map<double , map<usint, usint>>::iterator it;
	for (it = deltaToRingdimensionToTowerSizeMapper.begin(); it != deltaToRingdimensionToTowerSizeMapper.end(); it++)
	{
		cout << "Map for value: " << it->first << endl;
		std::map<usint, usint> maps = it->second;
		map<usint, usint>::iterator itInner;

		for (itInner = maps.begin(); itInner != maps.end(); itInner++) {
			cout << itInner->first << ":" << itInner->second << endl;
			}

	}

}

void ringReduceTest() {
	//usint m = 16;
	//float stdDev = 4;
	//usint size = 3;

	//vector<BigBinaryInteger> moduli(size);
	//moduli.reserve(4);
	//vector<BigBinaryInteger> rootsOfUnity(size);
	//rootsOfUnity.reserve(4);

	//BigBinaryInteger q("1");
	//BigBinaryInteger temp;
	//BigBinaryInteger modulus("1");

	//lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	//for (int i = 0; i < size; i++) {
	//	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	//	moduli[i] = q;
	//	rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
	//	modulus = modulus* moduli[i];
	//}

	//shared_ptr<ILDCRTParams> params(new ILDCRTParams(m, moduli, rootsOfUnity));

	//LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	//cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	//cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	//cryptoParams.SetElementParams(params);                // Set the initialization parameters.

	//CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
	//cc.Enable(ENCRYPTION);
	//cc.Enable(LEVELEDSHE);
	//cc.Enable(SHE);

	//LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	//vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	//IntPlaintextEncoding intArray(vectorOfInts);

	//ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	//vector<shared_ptr<Ciphertext<ILVectorArray2n>>> newCiphertext(ciphertext.size());

	//LPKeyPair<ILVectorArray2n> kp2 = cc.SparseKeyGen();

	//shared_ptr<LPEvalKey<ILVectorArray2n>> keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	//newCiphertext = cc.KeySwitch(keySwitchHint, ciphertext);

	//IntPlaintextEncoding intArrayNew;

	//cc.Decrypt(kp2.secretKey, newCiphertext, &intArrayNew, false);

	//ciphertext = cc.RingReduce(ciphertext, keySwitchHint);

	//ILVectorArray2n skSparseElement(kp2.secretKey->GetPrivateElement());
	//skSparseElement.SwitchFormat();
	//skSparseElement.Decompose();
	//skSparseElement.SwitchFormat();

	//kp2.secretKey->SetPrivateElement(skSparseElement);

	//IntPlaintextEncoding intArrayNewRR;

	//cc.Decrypt(kp2.secretKey, ciphertext, &intArrayNewRR, false);

	//IntPlaintextEncoding intArrayExpected({ 1,1,1,1 });

	//cout << intArrayNewRR << endl;

	ILVector2n::DestroyPreComputedSamples();
}