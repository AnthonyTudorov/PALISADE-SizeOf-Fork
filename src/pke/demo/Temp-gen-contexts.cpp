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
 *	@description generate serialized crypto contexts of various sizes
 */

#include <iostream>
#include <fstream>

#include "palisade.h"
#include "cryptocontexthelper.h"

using namespace std;
using namespace lbcrypto;

template<typename Element>
void GenContexts(EncodingParams encodingParams, float securityLevel, usint relinWindow, float dist, string nameroot) {

	string fn;
	usint m;

//	cout << "Trying LTV" << endl;
//	try {
//		Serialized ser;
//		auto cc = CryptoContextFactory<Element>::genCryptoContextLTV(
//				encodingParams, securityLevel, relinWindow, dist,
//				0, 2, 0);
//
//		if( cc ) {
//			if( cc->Serialize(&ser) ) {
//				fn = nameroot+"LTV";
//				cout << "Generating " << fn << endl;
//				SerializableHelper::WriteSerializationToFile(ser, fn);
//			}
//			else {
//				cout << "No serialization" << endl;
//			}
//		}
//		else {
//			cout << "No context" << endl;
//		}
//	} catch(...) {}

	cout << "Trying BFV" << endl;
	try {
		Serialized ser;
		auto cc = CryptoContextFactory<Element>::genCryptoContextBFV(
				encodingParams, securityLevel, relinWindow, dist,
				0, 4, 0);

		if( cc ) {
			if( cc->Serialize(&ser) ) {
				fn = nameroot+"BFV";
				cout << "Generating " << fn << endl;
				SerializableHelper::WriteSerializationToFile(ser, fn);
				m = cc->GetCyclotomicOrder();
			}
			else {
				cout << "No serialization" << endl;
			}
		}
		else {
			cout << "No context" << endl;
		}
	} catch(...) {}

	cout << "Trying BFVrns" << endl;
	try {
		Serialized ser;
		auto cc = CryptoContextFactory<Element>::genCryptoContextBFVrns(
				encodingParams, securityLevel, dist,
				0, 4, 0, OPTIMIZED, 2,
				relinWindow);

		if( cc ) {
			if( cc->Serialize(&ser) ) {
				fn = nameroot+"BFVrns";
				cout << "Generating " << fn << endl;
				SerializableHelper::WriteSerializationToFile(ser, fn);
				m = cc->GetCyclotomicOrder();
			}
			else {
				cout << "No serialization" << endl;
			}
		}
		else {
			cout << "No context" << endl;
		}
	} catch(...) {}

	//	static CryptoContext<Element> genCryptoContextBGV(shared_ptr<typename Element::Params> params,
	//		EncodingParams encodingParams,
	//		usint relinWindow, float stDev,
	//		MODE mode = RLWE, int depth = 1);
	//
	//	static CryptoContext<Element> genCryptoContextStehleSteinfeld(shared_ptr<typename Element::Params> params,
	//		EncodingParams encodingParams,
	//		usint relinWindow, float stDev, float stDevStSt, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	cout << "Trying Null" << endl;
	try {
		Serialized ser;
		auto cc = CryptoContextFactory<Element>::genCryptoContextNull(m, encodingParams);

		if( cc ) {
			if( cc->Serialize(&ser) ) {
				fn = nameroot+"Null";
				cout << "Generating " << fn << endl;
				SerializableHelper::WriteSerializationToFile(ser, fn);
			}
			else {
				cout << "No serialization" << endl;
			}
		}
		else {
			cout << "No context" << endl;
		}
	} catch(...) {}

}

int
main(int argc, char *argv[]) {

	const PlaintextModulus ptm = 1073872897;
	EncodingParams ep(new EncodingParamsImpl(ptm));
	double rootHermiteFactor = 1.004;
	usint relinWindow = 8;
	double sigma = 3.2;

	GenContexts<Poly>(ep, rootHermiteFactor, relinWindow, sigma, "CTX-POLY-");
	GenContexts<DCRTPoly>(ep, rootHermiteFactor, relinWindow, sigma, "CTX-DCRT-");

	return 0;
}
