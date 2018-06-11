/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 /*
BFV RNS testing programs
*/

#include <iostream>
#include <fstream>
#include <limits>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "palisade.h"

#include "cryptocontexthelper.h"
#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

#include <iterator>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

void Sharpen();
void KeyGen();
void Encrypt(size_t size);
void Evaluate(size_t size);
void Decrypt(size_t size);

int main(int argc, char **argv) {

	static int operation_flag;
	int opt;

	static struct option long_options[] =
	  {
		/* These options set a flag. */
		//{"verbose", no_argument,       &verbose_flag, 1},
		//{"brief",   no_argument,       &verbose_flag, 0},
		{"run", 	no_argument,       &operation_flag, 0},
		{"keygen", 	no_argument,       &operation_flag, 1},
		{"encrypt",   no_argument,     &operation_flag, 2},
		{"evaluate",   no_argument,     &operation_flag, 3},
		{"decrypt",   no_argument,     &operation_flag, 4},
		/* These options don�t set a flag.
		   We distinguish them by their indices. */
		{"size",  	required_argument, 			0, 's'},
		{"help",    no_argument, 0, 'h'},
		{0, 0, 0, 0}
	  };
	/* getopt_long stores the option index here. */
	int option_index = 0;

	size_t size = 0;

	while ((opt = getopt_long(argc, argv, "s:h", long_options, &option_index)) != -1) {
		switch (opt)
		{
			case 0:
				if (long_options[option_index].flag != 0)
					break;
				break;
			case 's':
				size = stoi(optarg);
				break;
			case 'h':
			default: /* '?' */
			  std::cerr<< "Usage: "<<argv[0]<<" <arguments> " <<std::endl
				   << "arguments:" <<std::endl
				   << "  --run simple run w/o serialization" <<std::endl
				   << "  --keygen --encrypt --evaluate --decrypt operation to run" <<std::endl
				   << "  -s --size size of the image"  <<std::endl
				   << "  -h --help prints this message" <<std::endl;
			  exit(EXIT_FAILURE);
		}
	}

	switch(operation_flag)
	{
		case 0:
			Sharpen();
			break;
		case 1:
			KeyGen();
			break;
		case 2:
			Encrypt(size);
			break;
		case 3:
			Evaluate(size);
			break;
		case 4:
			Decrypt(size);
			break;
		default:
			exit(EXIT_FAILURE);
	}

	//Sharpen();

	//cin.get();
	return 0;
}

#define PROFILE

CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName)
{

	std::cout << "Deserializing the crypto context...";

	Serialized	ccSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);

	std::cout << "Completed" << std::endl;

	return cc;
}


CryptoContext<DCRTPoly> DeserializeContextWithEvalKeys(const string& ccFileName, const string& emFileName)
{

	std::cout << "Deserializing the crypto context...";

	Serialized	ccSer, emSer, esSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	if (SerializableHelper::ReadSerializationFromFile(emFileName, &emSer) == false) {
		cerr << "Could not read the eval mult key file" << endl;
		return 0;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);

	if( cc->DeserializeEvalMultKey(emSer) == false ) {
		cerr << "Could not deserialize the eval mult key file" << endl;
		return 0;
	}

	std::cout << "Completed" << std::endl;

	return cc;
}

void KeyGen() {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeKeyGen(0.0), timeSer(0.0), timeTotal(0.0);

	usint ptm = 8192;
	double sigma = 3.19;
	double rootHermiteFactor = 1.004;

	std::cout << "Generating parameters...";

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED,3,30,60);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB() << std::endl;

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "Completed" << std::endl;

	std::cout << "Generating keys...";

	// Key generation
	LPKeyPair<DCRTPoly> kp;

	TIC(t1);

	kp = cryptoContext->KeyGen();
	cryptoContext->EvalMultKeyGen(kp.secretKey);

	timeKeyGen = TOC(t1);

	std::cout << "Completed" << std::endl;

	TIC(t1);

	std::cout << "Serializing crypto context...";

	Serialized ctxt;

	if (cryptoContext->Serialize(&ctxt)) {
		if (!SerializableHelper::WriteSerializationToFile(ctxt, "demoData/cryptocontext.txt")) {
			cerr << "Error writing serialization of the crypto context to cryptocontext.txt" << endl;
			return;
		}
	}
	else {
		cerr << "Error serializing the crypto context" << endl;
		return;
	}

	std::cout << "Completed" << std::endl;

	std::cout << "Serializing private and public keys...";

    if(kp.publicKey && kp.secretKey) {
		Serialized pubK, privK;

		if(kp.publicKey->Serialize(&pubK)) {
			if(!SerializableHelper::WriteSerializationToFile(pubK, "demoData/PUB.txt")) {
			cerr << "Error writing serialization of public key" << endl;
			return;
			}
		} else {
			cerr << "Error serializing public key" << endl;
			return;
		}

		if(kp.secretKey->Serialize(&privK)) {
			if(!SerializableHelper::WriteSerializationToFile(privK, "demoData/PRI.txt")) {
			cerr << "Error writing serialization of private key" << endl;
			return;
			}
		} else {
			cerr << "Error serializing private key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating keys" << endl;
	}

	std::cout << "Completed" << std::endl;

	std::cout << "Serializing eval mult key...";

	Serialized emKeys;

	if (cryptoContext->SerializeEvalMultKey(&emKeys)) {
		if (!SerializableHelper::WriteSerializationToFile(emKeys, "demoData/EVALMULT.txt")) {
			cerr << "Error writing serialization of the eval mult key" << endl;
			return;
		}
	}
	else {
		cerr << "Error serializing eval mult key" << endl;
		return;
	}

	std::cout << "Completed" << std::endl;

	timeSer = TOC(t1);

	timeTotal = TOC(t_total);

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Encrypt(size_t size) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeEnc(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

	CryptoContext<DCRTPoly> cryptoContext = DeserializeContext("demoData/cryptocontext.txt");

	string pubKeyLoc = "demoData/PUB.txt";
	Serialized kser;
	if(SerializableHelper::ReadSerializationFromFile(pubKeyLoc, &kser) == false) {
		cerr << "Could not read public key" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPublicKey<DCRTPoly> pk = cryptoContext->deserializePublicKey(kser);

	timeSer = TOC(t1);

	// Read the image file
	int width, height, bpp;

	/*char path[] = "";
	sprintf(path,"demoData/Baboon%lu.png",(long unsigned int)size);
	unsigned char* data = stbi_load( path, &width, &height, &bpp, 1 );*/

	string path = "demoData/Baboon" + to_string(size) + ".png";
	const char *pathc = path.c_str();

	unsigned char* data = stbi_load( pathc, &width, &height, &bpp, 1 );
	cout << width << "," << height << "," << bpp << endl;

	string path2 = "demoData/Baboon" + to_string(size) + "COPY.png";
	stbi_write_png(path2.c_str(), width, height, 1, data, width*1);

	std::cout << "Input 2D array" << std::endl;

	vector<vector<Plaintext>> plaintext(height);

	for(int i = 0; i < height; i++)
	{
		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			std::cout << (unsigned int)(unsigned char)data[i*width+k] << " ";
			plaintext[i].push_back(cryptoContext->MakeFractionalPlaintext( (unsigned int)data[i*width + k]));
		}
		std::cout << " ] " << std::endl;
	}

	vector<vector<Ciphertext<DCRTPoly>>> image(height);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {
			TIC(t1);
			imageRow[k] = cryptoContext->Encrypt(pk, plaintext[i][k]);
			timeEnc += TOC(t1);

			TIC(t1);
			string ciphertextname ="demoData/ciphertext-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";
			ofstream ctSer(ciphertextname, ios::binary);

			if (!ctSer.is_open()) {
				cerr << "could not open output file " << ciphertextname << endl;
				return;
			}

			Serialized cSer;
			if (imageRow[k]->Serialize(&cSer)) {
				if (!SerializableHelper::WriteSerializationToFile(cSer, ciphertextname)) {
					cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing ciphertext" << endl;
				return;
			}

			timeSer += TOC(t1);
		}
		image[i] = imageRow;
	}

	timeTotal = TOC(t_total);

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Encryption time:        " << "\t" << timeEnc << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Evaluate(size_t size)
{

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeEval(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

    CryptoContext<DCRTPoly> cryptoContext = DeserializeContextWithEvalKeys("demoData/cryptocontext.txt","demoData/EVALMULT.txt");

    int height = size;
    int width = size;

    size_t truncatedBits = 1;

    std::cout << "Deserializing ciphertexts..." ;

    vector<vector<Ciphertext<DCRTPoly>>> image(height);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {

			string ciphertextname = "demoData/ciphertext-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";

			Serialized kser;
			if(SerializableHelper::ReadSerializationFromFile(ciphertextname, &kser) == false) {
					cerr << "Could not read ciphertext" << endl;
					return;
				}

			Ciphertext<DCRTPoly> ct = cryptoContext->deserializeCiphertext(kser);
			if(ct == NULL) {
				cerr << "Could not deserialize ciphertext" << endl;
				return;
			}
			else{
				imageRow[k] = ct;
			}
		}

		image[i] = imageRow;

	}

	std::cout << "Completed" << std::endl;

	timeSer = TOC(t1);

	std::cout << "Computing..." ;

	vector<vector<int>> weightsRaw = {{1, 1, 1}, {1, -8, 1}, {1, 1, 1}};

	vector<vector<Plaintext>> weight(weightsRaw.size());

	for(int i = 0; i < (int)weightsRaw.size(); i++)
	{
		for(int k = 0; k < (int)weightsRaw[0].size(); k++) {
			weight[i].push_back(cryptoContext->MakeFractionalPlaintext(weightsRaw[i][k]));
		}
	}

	vector<vector<Ciphertext<DCRTPoly>>> image2(image);

	TIC(t1);

	for(int x = 1; x < height-1; x++)
	{
		for(int y = 1; y < width-1; y++) {
			Ciphertext<DCRTPoly> pixel_value;
			for(int i = -1; i < 2; i++)
			{
				for(int j = -1; j < 2; j++) {
					if (pixel_value == NULL)
						pixel_value = cryptoContext->EvalMult(image[x+i][y+j],weight[i+1][j+1]);
					else
						pixel_value = cryptoContext->EvalAdd(pixel_value,cryptoContext->EvalMult(image[x+i][y+j],weight[i+1][j+1]));
				}
			}
			image2[x][y] = cryptoContext->EvalSub(image[x][y],cryptoContext->EvalRightShift(pixel_value,truncatedBits));

		}
	}

	timeEval = TOC(t1);

	std::cout << "Completed" << std::endl;

	std::cout << "Serializing the results..." ;

	TIC(t1);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {

			string ciphertextname ="demoData/ciphertext-result-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";
			ofstream ctSer(ciphertextname, ios::binary);

			if (!ctSer.is_open()) {
				cerr << "could not open output file " << ciphertextname << endl;
				return;
			}

			Serialized cSer;
			if (image2[i][k]->Serialize(&cSer)) {
				if (!SerializableHelper::WriteSerializationToFile(cSer, ciphertextname)) {
					cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing ciphertext" << endl;
				return;
			}
		}

	}

	timeSer += TOC(t1);

	std::cout << "Completed" << std::endl;

	timeTotal = TOC(t_total);

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Evaluation time:        " << "\t" << timeEval << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Decrypt(size_t size) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeDec(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

	CryptoContext<DCRTPoly> cryptoContext = DeserializeContext("demoData/cryptocontext.txt");

    int height = size;
    int width = size;

	string privKeyLoc = "demoData/PRI.txt";
	Serialized kser;
	if(SerializableHelper::ReadSerializationFromFile(privKeyLoc, &kser) == false) {
		cerr << "Could not read privatekey" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPrivateKey<DCRTPoly> sk = cryptoContext->deserializeSecretKey(kser);

    std::cout << "Deserializing ciphertexts..." ;

    vector<vector<Ciphertext<DCRTPoly>>> image2(height);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {

			string ciphertextname = "demoData/ciphertext-result-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";

			Serialized kser;
			if(SerializableHelper::ReadSerializationFromFile(ciphertextname, &kser) == false) {
					cerr << "Could not read ciphertext" << endl;
					return;
				}

			Ciphertext<DCRTPoly> ct = cryptoContext->deserializeCiphertext(kser);
			if(ct == NULL) {
				cerr << "Could not deserialize ciphertext" << endl;
				return;
			}
			else{
				imageRow[k] = ct;
			}
		}

		image2[i] = imageRow;

	}

	std::cout << "Completed" << std::endl;

	timeSer = TOC(t1);

    std::cout << "Decrypting..." ;

	vector<vector<Plaintext>> result(height);

	TIC(t1);

	for(int i = 0; i < height; i++)
	{
		result[i] = vector<Plaintext>(width);
		for(int k = 0; k < width; k++) {
			cryptoContext->Decrypt(sk, image2[i][k],&result[i][k]);
		}
	}

	timeDec = TOC(t1);

	std::cout << "Completed" << std::endl;

	string path = "demoData/Baboon" + to_string(size) + "OUT.png";
	const char *pathc = path.c_str();
	unsigned char *data = new unsigned char[height*width];
	for(int i = 0; i < height; i++)
	{
		for(int k = 0; k < width; k++) {
			auto v = result[i][k]->GetIntegerValue();
			if( v < 0 ) v = 0;
			else if( v > 0xff ) v = 0xff;
			data[i*width + k] = v;
		}
	}

//	for(int i = 0; i < height; i++)
//	{
//		std::cout << " [ ";
//		for(int k = 0; k < width; k++) {
//			std::cout << (unsigned int)(unsigned char)data[i*width+k] << " ";
//			plaintext[i].push_back(cryptoContext->MakeFractionalPlaintext( (unsigned int)(unsigned char)data[i*width + k]));
//		}
//		std::cout << " ] " << std::endl;
//	}
	stbi_write_png( pathc, width, height, 1, data, width*1 );
	delete[] data;

	cout << width << "," << height << endl;
	std::cout << "The result is" << std::endl;

	for(int i = 0; i < height; i++)
	{
		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			std::cout << result[i][k] << " ";
		}
		std::cout << " ] " << std::endl;
		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			std::cout << (result[i][k]->GetIntegerValue() & 0xff) << " ";
		}
		std::cout << " ] " << std::endl;
	}

	timeTotal = TOC(t_total);

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Decryption time:        " << "\t" << timeDec << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Sharpen() {

	std::cout << "\n===========SHARPENING DEMO===============: " << std::endl;

	std::cout << "\nThis code demonstrates the implementation of 8-neighbor Laplacian image sharpening algorithm using BFVrns. " << std::endl;

	usint ptm = 8192;
	double sigma = 3.19;
	double rootHermiteFactor = 1.004;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED,3,30,60);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB() << std::endl;

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	// Key generation
	LPKeyPair<DCRTPoly> keyPair;

	keyPair = cryptoContext->KeyGen();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	size_t truncatedBits = 1;

	// Read the image file
	int width, height, bpp;
	unsigned char* data = stbi_load( "demoData/Baboon8.png", &width, &height, &bpp, 1 );

	vector<vector<Plaintext>> plaintext(height);

	for(int i = 0; i < height; i++)
	{
		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			std::cout << (unsigned int)(unsigned char)data[i*width+k] << " ";
			plaintext[i].push_back(cryptoContext->MakeFractionalPlaintext( (unsigned int)(unsigned char)data[i*width + k]));
		}
		std::cout << " ] " << std::endl;
	}

	vector<vector<Ciphertext<DCRTPoly>>> image(height);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {
			imageRow[k] = cryptoContext->Encrypt(keyPair.publicKey, plaintext[i][k]);
		}
		image[i] = imageRow;
	}

	vector<vector<int>> weightsRaw = {{1, 1, 1}, {1, -8, 1}, {1, 1, 1}};

	vector<vector<Plaintext>> weight(weightsRaw.size());

	for(int i = 0; i < (int)weightsRaw.size(); i++)
	{
		for(int k = 0; k < (int)weightsRaw[0].size(); k++) {
			weight[i].push_back(cryptoContext->MakeFractionalPlaintext(weightsRaw[i][k]));
		}
	}

	vector<vector<Ciphertext<DCRTPoly>>> image2(image);

	for(int x = 1; x < height-1; x++)
	{
		for(int y = 1; y < width-1; y++) {
			Ciphertext<DCRTPoly> pixel_value;
			for(int i = -1; i < 2; i++)
			{
				for(int j = -1; j < 2; j++) {
					if (pixel_value == NULL)
						pixel_value = cryptoContext->EvalMult(image[x+i][y+j],weight[i+1][j+1]);
					else
						pixel_value = cryptoContext->EvalAdd(pixel_value,cryptoContext->EvalMult(image[x+i][y+j],weight[i+1][j+1]));
				}
			}
			image2[x][y] = cryptoContext->EvalSub(image[x][y],cryptoContext->EvalRightShift(pixel_value,truncatedBits));
		}
	}

	vector<vector<Plaintext>> result(height);

	for(int i = 0; i < height; i++)
	{
		result[i] = vector<Plaintext>(width);
		for(int k = 0; k < width; k++) {
			cryptoContext->Decrypt(keyPair.secretKey, image2[i][k],&result[i][k]);
		}
	}

	std::cout << "The result is" << std::endl;

	for(int i = 0; i < height; i++)
	{
		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			std::cout << result[i][k] << " ";
		}
		std::cout << " ] " << std::endl;
	}

}

