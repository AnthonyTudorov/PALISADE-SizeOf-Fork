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
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

/*
template<typename Element>
inline CryptoContext<Element>
GenTestCryptoContext(const string& name, usint ORDER, PlaintextModulus ptm, usint bits=DefaultQbits, usint towers=DefaultT) {
	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params>(ORDER, bits, towers);
	CryptoContext<Element> cc;

	if( name == "Null" ) {
		cc = CryptoContextFactory<Element>::genCryptoContextNull(ORDER, ptm);
	}
	else if( name == "LTV" )
		cc = CryptoContextFactory<Element>::genCryptoContextLTV(p, ptm, 1, 4);
	else if( name == "StSt" )
		cc = CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5);
	else if( name == "BGV_rlwe" )
		cc = CryptoContextFactory<Element>::genCryptoContextBGV(p, ptm, 1, 4, RLWE);
	else if( name == "BGV_opt" )
		cc = CryptoContextFactory<Element>::genCryptoContextBGV(p, ptm, 1, 4, OPTIMIZED);
	else if( name == "BFV_rlwe" )
		cc = GenCryptoContextBFV<Element>(ORDER, ptm, bits, towers, RLWE);
	else if( name == "BFV_opt" )
		cc = GenCryptoContextBFV<Element>(ORDER, ptm, bits, towers, OPTIMIZED);
	else if( name == "BFVrns_rlwe" )
		cc = GenCryptoContextBFVrns<Element>(ptm, RLWE);
	else if( name == "BFVrns_opt" )
		cc = GenCryptoContextBFVrns<Element>(ptm, OPTIMIZED);
 */

vector<string> ctxts = { "Null", "LTV", "StSt", "BGV_rlwe", "BGV_opt", "BFV_rlwe", /*"BFV_opt",*/ "BFVrns_rlwe", "BFVrns_opt" };

template<typename Element>
void GenContexts(usint ORDER, PlaintextModulus ptm, string nameroot) {

	string fn = nameroot + to_string(ORDER) + "-";

	for( string cx : ctxts ) {
		cout << "Trying " << cx << endl;

		try {
			auto cc = GenTestCryptoContext<Element>(cx, ORDER, ptm);

			if( cc ) {
				string tfn = fn+cx;
				cout << "Generating " << tfn << endl;
				Serializable::SerializeToFile(tfn, cc, Serializable::Type::JSON);
			}
			else {
				cout << "No context" << endl;
			}
		} catch(...) {}
	}
}

int
main(int argc, char *argv[]) {

	const PlaintextModulus ptm = 1073872897;

	for( usint ORDER = 2048; ORDER < 8192; ORDER *= 2 ) {
		GenContexts<Poly>(ORDER, ptm, "CTX-POLY-");
		GenContexts<DCRTPoly>(ORDER, ptm, "CTX-DCRT-");
	}

	return 0;
}
