//LAYER 3 : CRYPTO DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/14/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:	
	This code provides the core proxy re-encryption functionality.

All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.

This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
*/

#include "lwecrypt.h"

namespace lbcrypto {

template <class T,class P>
bool LP_Algorithm_LWE_NTRU<T,P>::KeyGen(LP_PublicKey<Element,ElementParams> &publicKey, 
		LP_PrivateKey<Element,ElementParams> &privateKey, 
		DiscreteGaussianGenerator &dgg) const
{
	const LP_CryptoParameters<Element,ElementParams> &cryptoParams = privateKey.GetAbstractCryptoParameters();
	const ElementParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	//need to be written cleaner; references to BigBinaryVector should be removed
	//Add a Set accessor to ILVector2n to set individual element of vector
	//then update the three lines below
	BigBinaryVector &fHandle = const_cast<BigBinaryVector&>(f.GetValues());
	const BigBinaryInteger &fIntHandle = fHandle.GetValAtIndex(0);
	fHandle.SetValAtIndex(0,fIntHandle+BigBinaryInteger::ONE);

	//cout<<"f="<<f.GetValues()<<endl;

	f.SwitchFormat();

	privateKey.SetPrivateElement(f);
	privateKey.AccessAbstractCryptoParameters() = cryptoParams;

	Element g(dgg,elementParams,Format::COEFFICIENT);
	g.SwitchFormat();

	privateKey.SetPrivateErrorElement(g);

	//public key is generated
	privateKey.MakePublicKey(publicKey);

	return true;
}

template <class T,class P>
void LP_Algorithm_LWE_NTRU<T,P>::Encrypt(const LP_PublicKey<Element,ElementParams> &publicKey, 
				DiscreteGaussianGenerator &dgg, 
				const ByteArray &plaintext, 
				Element *ciphertext) const
{

	const LP_CryptoParameters<Element,ElementParams> &cryptoParams = publicKey.GetAbstractCryptoParameters();
	const ElementParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element m(elementParams);
	
	m.EncodeElement(plaintext,p);

	//cout<<"m original ="<<m.GetValues()<<endl;

	m.SwitchFormat();

	const Element &h = publicKey.GetPublicElement();

	Element s(dgg,elementParams);
	Element e(dgg,elementParams);

	//Element a(p*e + m);
	//a.SwitchFormat();

	Element c(elementParams);

	c = h*s + p*e + m;

	*ciphertext = c;

}

template <class T,class P>
DecodingResult LP_Algorithm_LWE_NTRU<T,P>::Decrypt(const LP_PrivateKey<Element,ElementParams> &privateKey, 
				const Element &ciphertext, 
				ByteArray *plaintext) const
{
	const LP_CryptoParameters<Element,ElementParams> &cryptoParams = privateKey.GetAbstractCryptoParameters();
	const ElementParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element c(elementParams);
	c = ciphertext;

	Element b(elementParams);
	Element f = privateKey.GetPrivateElement(); //add const

	b = f*c;

	b.SwitchFormat();

	//Element m(elementParams);
	//m = b.Mod(p);

	//need to be written cleaner - as an Element
	BigBinaryVector mTemp(b.ModByTwo());
	Element m(elementParams);
	m.SetValues(mTemp,Format::COEFFICIENT);

	//cout<<"m ="<<m.GetValues()<<endl;

	m.DecodeElement(plaintext,p);

	return DecodingResult((*plaintext).length());
}


}  // namespace lbcrypto ends
