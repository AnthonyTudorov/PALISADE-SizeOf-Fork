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
// This program demonstrates the use of the PALISADE library to perform SHE operations
//
// All PALISADE functionality takes place as a part of a CryptoContext, and so the first
// step in using PALISADE is creating a CryptoContext
//
// A CryptoContext can be created on the fly by passing parameters into a method provided
// in the CryptoContextFactory.
// A CryptoContext can be custom tuned for your particular application by using parameter generation
// A CryptoContext can be constructed from one of a group of named, predetermined parameter sets
//
// This program uses the "group of named predetermined sets" method. Pass the parameter set name to the
// program and it will use that set. Pass no names and it will tell you all the available names.
// Use the -v option and the program will be verbose as it operates
 */

#include <iostream>
#include <fstream>
#include <string>
#include <iterator>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "cryptocontextparametersets.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

////////////////////////////////////////////////////////////
// This program demonstrates the use of the PALISADE library to perform SHE operations
//
// All PALISADE functionality takes place as a part of a CryptoContext, and so the first
// step in using PALISADE is creating a CryptoContext
//
// A CryptoContext can be created on the fly by passing parameters into a method provided
// in the CryptoContextFactory.
// A CryptoContext can be custom tuned for your particular application by using parameter generation
// A CryptoContext can be constructed from one of a group of named, predetermined parameter sets
//
// This program uses the "group of named predetermined sets" method. Pass the parameter set name to the
// program and it will use that set. Pass no names and it will tell you all the available names.
// Use the -v option and the program will be verbose as it operates

int main(int argc, char *argv[])
{
	string parmSetName;
	bool beVerbose = false;
	bool haveName = false;

	// Process parameters, find the parameter set name specified on the command line
	for( int i=1; i<argc; i++ ) {
		string parm( argv[i] );

		if( parm[0] == '-' ) {
			if( parm == "-v" )
				beVerbose = true;
			else {
				cout << "Unrecognized parameter " << parm << endl;
				return 1;
			}
		}

		else {
			if( haveName ) {
				cout << "Cannot specify multiple parameter set names" << endl;
				return 1;
			}

			haveName = true;
			parmSetName = parm;

		}
	}

	// If a name has been specified, make sure it is recognized
	if( haveName ) {
		auto parmfind = CryptoContextParameterSets.find(parmSetName);
		if( parmfind == CryptoContextParameterSets.end() ) {
			cout << "Parameter set " << parmSetName << " is not a recognized name" << endl;
			haveName = false;
		}
	}

	// no name specified? print out the names of all available parameter sets
	if( !haveName ) {
		cout << "Available crypto parameter sets are:" << endl;
		CryptoContextHelper::printAllParmSetNames(cout);
		return 1;
	}

	// Construct a crypto context for this parameter set

	if( beVerbose ) cout << "Initializing crypto system" << endl;

	CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(parmSetName);

	// enable features that you wish to use
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// for this demo we reset the plaintext modulus and try ParamsGen
	cc.GetCryptoParameters()->SetPlaintextModulus(4);

	try {
		if( beVerbose )
			cout << "Running params gen" << endl;
		cc.GetEncryptionAlgorithm()->ParamsGen(cc.GetCryptoParameters(), 0, 1);
	} catch(...) {
		// ignore for schemes w/o Param Gen
		if( beVerbose )
			cout << "Running params gen failed, continuing..." << endl;
	}

	if( beVerbose ) {
		CryptoContextHelper::printParmSet(cout, parmSetName);
		cout << *cc.GetCryptoParameters() << endl;
	}

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3, 1, 2, 3, 2, 2, 1, 1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3, 0, 0 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	if( beVerbose ) cout << "Running key generation" << endl;

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	if( !kp.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	if( beVerbose ) cout << "Running encryption" << endl;

	ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1);
	ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2);

	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////

	if( beVerbose ) cout << "Performing EvalAdd" << endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAdd;
	shared_ptr<Ciphertext<ILVector2n>> ciphertextAddResult;

	ciphertextAddResult = cc.EvalAdd(ciphertext1[0], ciphertext2[0]);
	ciphertextAdd.push_back(ciphertextAddResult);

	if( beVerbose ) cout << "Running decryption on Add result" << std::endl;

	IntPlaintextEncoding plaintextAddTemp;

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertextAdd, &plaintextAddTemp);

	plaintextAddTemp.resize(plaintextAdd.size());

	if( beVerbose ) {
		cout << plaintext1 << " + \n" << plaintext2 << " = \n" << plaintextAddTemp;
		if( plaintextAddTemp == plaintextAdd )
			cout << " ... CORRECT!";
		else
			cout << " ... INCORRECT!";
		cout << endl;
	}

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	if( beVerbose ) cout << "Generating evaluation key" << endl;

	cc.EvalMultKeyGen(kp.secretKey);

	if( beVerbose ) cout << "Performing EvalMult" << endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextMult;
	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempMult;

	ciphertextTempMult = cc.EvalMult(ciphertext1[0], ciphertext2[0]);

	ciphertextMult.push_back(ciphertextTempMult);

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	if( beVerbose ) cout << "Running decryption on Mult result" << endl;

	IntPlaintextEncoding plaintextNewMult;

	result = cc.Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult);

	plaintextNewMult.resize(plaintextMult.size());

	if( beVerbose ) {
		cout << plaintext1 << " * \n" << plaintext2 << " = \n" << plaintextNewMult << endl;
		if( plaintextNewMult == plaintextMult )
			cout << " ... CORRECT!";
		else
			cout << " ... INCORRECT!";
		cout << endl;
	}

	return 0;
}
