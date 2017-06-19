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

#include "palisade.h"
#include "cryptocontextgen.h"

using namespace std;

void TestPowersAndDecompose(CryptoContext<ILVector2n> cc, ILVector2n& randomVec) {

	const shared_ptr<ILVector2n::Params> eParms = std::dynamic_pointer_cast<ILVector2n::Params>(cc.GetElementParams());
	cout << *eParms << endl;

	vector<ILVector2n> decomp = randomVec.BaseDecompose(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "BaseDecompose result is " << decomp.size() << " vectors" << endl;

	usint nBits = cc.GetCryptoParameters()->GetRelinWindow();
	ILVector2n answer(cc.GetElementParams(), EVALUATION, true); // zero vector
	for (usint i = 0; i < decomp.size(); i++) {
		ILVector2n thisProduct = decomp[i] * ILVector2n::Integer(2).ModExp( typename ILVector2n::Integer(i * nBits), cc.GetElementParams()->GetModulus());
		answer += thisProduct;
	}

	if (randomVec == answer)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;

	ILVector2n randomDgg(cc.GetCryptoParameters()->GetDiscreteGaussianGenerator(), cc.GetElementParams());
	vector<ILVector2n> pows = randomDgg.PowersOfBase(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "PowersOfBase result is " << decomp.size() << " vectors" << endl;

	ILVector2n answer2(cc.GetElementParams(), EVALUATION, true); // zero vector
	for (usint i = 0; i < pows.size(); i++) {
		answer2 += decomp[i] * pows[i];
	}
	if ((randomVec * randomDgg) == answer2)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;
}

void TestPowersAndDecompose(CryptoContext<ILDCRT2n> cc, ILDCRT2n& randomVec) {

	const shared_ptr<ILDCRT2n::Params> eParms = std::dynamic_pointer_cast<ILDCRT2n::Params>(cc.GetElementParams());
	cout << *eParms << endl;

	vector<ILDCRT2n> decomp = randomVec.BaseDecompose(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "BaseDecompose result is " << decomp.size() << " vectors" << endl;

	usint nBits = cc.GetCryptoParameters()->GetRelinWindow();
	ILDCRT2n answer(cc.GetElementParams(), EVALUATION, true); // zero vector

	std::vector<ILDCRT2n::Integer> mods(eParms->GetParams().size());
	for( usint i = 0; i < eParms->GetParams().size(); i++ )
		mods[i] = ILDCRT2n::Integer(eParms->GetParams()[i]->GetModulus().ConvertToInt());

	for (usint i = 0; i < decomp.size(); i++) {
		ILDCRT2n::Integer twoPow( ILDCRT2n::Integer(2).Exp(i * nBits) );
		vector<ILDCRT2n::ILVectorType> scalars(eParms->GetParams().size());

		for( usint t = 0; t < eParms->GetParams().size(); t++ ) {
			ILDCRT2n::Integer factor = twoPow % mods[t];
			ILDCRT2n::ILVectorType thisScalar(eParms->GetParams()[t], EVALUATION);
			thisScalar = factor.ConvertToInt();
			scalars[t] = thisScalar;
		}
		ILDCRT2n thisProduct(scalars);

		answer += thisProduct * decomp[i];
	}

	if (randomVec == answer)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;

	ILDCRT2n randomDgg(cc.GetCryptoParameters()->GetDiscreteGaussianGenerator(), cc.GetElementParams());
	vector<ILDCRT2n> pows = randomDgg.PowersOfBase(cc.GetCryptoParameters()->GetRelinWindow());
	cout << "PowersOfBase result is " << decomp.size() << " vectors" << endl;

	ILDCRT2n answer2(cc.GetElementParams(), EVALUATION, true); // zero vector
	for (usint i = 0; i < pows.size(); i++) {
		answer2 += decomp[i] * pows[i];
	}
	if ((randomVec * randomDgg) == answer2)
		cout << "Success!" << endl;
	else
		cout << "Failure!" << endl;
}

int main()
{
	const usint ORDER = 8;
	const usint PTM = 2;
	const usint TOWERS = 3;
	const usint BITS = 34;

	CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM, BITS);
	cout << "ILVector2n modulus " << cc.GetElementParams()->GetModulus() << " order " << ORDER << " ptm is " << PTM << " relin window is " << cc.GetCryptoParameters()->GetRelinWindow() << endl;

	typename ILVector2n::DugType dug;
	dug.SetModulus( cc.GetElementParams()->GetModulus() );

	ILVector2n randomVec(dug, cc.GetElementParams());

	TestPowersAndDecompose(cc, randomVec);


	for ( usint i = 1; i <= TOWERS; i++ ) {
		CryptoContext<ILDCRT2n> cc2 = GenCryptoContextElementArrayBV(ORDER, i, PTM, BITS);
		cout << "ILDCRT2n " << i << " towers, modulus " << cc2.GetElementParams()->GetModulus() << " order " << ORDER << " ptm is " << PTM << " relin window is " << cc2.GetCryptoParameters()->GetRelinWindow() << endl;

		ILDCRT2n randomVecA(randomVec, cc2.GetElementParams());

		TestPowersAndDecompose(cc2, randomVecA);
	}

	return 0;
}