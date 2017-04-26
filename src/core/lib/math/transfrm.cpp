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

Description:
This file contains the linear transform interface functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#include "transfrm.h"

namespace lbcrypto {


//static Initializations
template<typename IntType, typename VecType>
NumberTheoreticTransform<IntType,VecType>* NumberTheoreticTransform<IntType,VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
ChineseRemainderTransform<IntType,VecType>* ChineseRemainderTransform<IntType,VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
VecType* ChineseRemainderTransform<IntType,VecType>::m_rootOfUnityInverseTable = 0;

template<typename IntType, typename VecType>
VecType* ChineseRemainderTransform<IntType,VecType>::m_rootOfUnityTable = 0;

template<typename IntType, typename VecType>
ChineseRemainderTransformFTT<IntType,VecType>* ChineseRemainderTransformFTT<IntType,VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
BluesteinFFT<IntType, VecType>* BluesteinFFT<IntType, VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
ChineseRemainderTransformArb<IntType, VecType>* ChineseRemainderTransformArb<IntType, VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityInverseTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformArb<IntType, VecType>::m_cyclotomicPolyMap;

template<typename IntType, typename VecType>
std::map<IntType, VecType> BluesteinFFT<IntType, VecType>::m_rootOfUnityTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> BluesteinFFT<IntType, VecType>::m_rootOfUnityInverseTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> BluesteinFFT<IntType, VecType>::m_powersTableByRoot;

template<typename IntType, typename VecType>
std::map<IntType, IntType> BluesteinFFT<IntType, VecType>::m_NTTModulus;

DiscreteFourierTransform* DiscreteFourierTransform::m_onlyInstance = 0;
std::complex<double>* DiscreteFourierTransform::rootOfUnityTable = 0;
}
//TODO: why is this namespace split like this? 
namespace lbcrypto {
template<typename IntType, typename VecType>
NumberTheoreticTransform<IntType,VecType>& NumberTheoreticTransform<IntType,VecType>::GetInstance() {
	if (m_onlyInstance == NULL) {
		m_onlyInstance = new NumberTheoreticTransform<IntType,VecType>();//lazy instantiation
	}
	return *m_onlyInstance;
}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename IntType, typename VecType>
VecType NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(const VecType& element, const VecType &rootOfUnityTable, const usint cycloOrder) {
        bool dbg_flag = false;
	usint n = cycloOrder;
	VecType result(n);
	result.SetModulus(element.GetModulus());

	//reverse coefficients (bit reversal)
	usint msb = GetMSB32(n - 1);
	for (usint i = 0; i<n; i++)
		result.SetValAtIndex(i, element.GetValAtIndex(ReverseBits(i, msb)));

	IntType omegaFactor;
	IntType product;
	IntType butterflyPlus;
	IntType butterflyMinus;
	/*Ring dimension factor calculates the ratio between the cyclotomic order of the root of unity table
		  that was generated originally and the cyclotomic order of the current VecType. The twiddle table
		  for lower cyclotomic orders is smaller. This trick only works for powers of two cyclotomics.*/ 
	float ringDimensionFactor = ((float)rootOfUnityTable.GetLength()) / (float)cycloOrder;

	//YSP mu is not needed for native data types or BE 6
#if MATHBACKEND != 6
	//Precompute the Barrett mu parameter
	IntType temp(IntType::ONE);
	temp <<= 2 * element.GetModulus().GetMSB() + 3;
	IntType mu = temp.DividedBy(element.GetModulus());
	//std::cout << "NTTFwd mod,tmp,mu" << element.GetModulus() << "," << temp << "," << mu << std::endl;
#endif
#if MATHBACKEND == 6
	IntType modulus = element.GetModulus();
#endif

	for (usint m = 2; m <= n; m = 2 * m)
	{

		for (usint j = 0; j<n; j = j + m)
		{
			for (usint i = 0; i <= m / 2 - 1; i++)
			{

				usint x = (2 * i*n / m ) * ringDimensionFactor;

				const IntType& omega = rootOfUnityTable.GetValAtIndex(x);

				usint indexEven = j + i;
				usint indexOdd = j + i + m / 2;

				if (result.GetValAtIndex(indexOdd).GetMSB()>0)
				{

					if (result.GetValAtIndex(indexOdd).GetMSB() == 1)
						omegaFactor = omega;
					else
					{
#if MATHBACKEND !=6
						//omegaFactor = omega*result.GetValAtIndex(indexOdd);
						//omegaFactor.ModBarrettInPlace(element.GetModulus(), mu);
						omegaFactor = omega.ModBarrettMul(result.GetValAtIndex(indexOdd),element.GetModulus(), mu);

#else
						omegaFactor = omega.ModMulFast(result.GetValAtIndex(indexOdd),modulus);
#endif
						DEBUG("omegaFactor "<<omegaFactor);
					}
#if  MATHBACKEND !=6
					butterflyPlus = result.GetValAtIndex(indexEven);
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= element.GetModulus())
						butterflyPlus -= element.GetModulus();

					butterflyMinus = result.GetValAtIndex(indexEven);
					if (result.GetValAtIndex(indexEven) < omegaFactor)
						butterflyMinus += element.GetModulus();
					butterflyMinus -= omegaFactor;

					result.SetValAtIndex(indexEven, butterflyPlus);
					result.SetValAtIndex(indexOdd, butterflyMinus);
#else
					//result[indexOdd] = result[indexEven]-omegaFactor;
					result[indexOdd] = result[indexEven].ModSubFast(omegaFactor,modulus);
					//result[indexEven]+=omegaFactor;
					result[indexEven] = result[indexEven].ModAddFast(omegaFactor,modulus);
#endif
				}
				else
				  //result.SetValAtIndex(indexOdd, result.GetValAtIndex(indexEven));
				  result[indexOdd] = result[indexEven];

			}

		}
	}

	return result;

}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename IntType, typename VecType>
VecType NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable, const usint cycloOrder) {

	VecType ans = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(element, rootOfUnityInverseTable, cycloOrder);

	ans.SetModulus(element.GetModulus());
	//TODO:: note this could be stored
#if 1//MATHBACKEND !=6
	ans = ans.ModMul(IntType(cycloOrder).ModInverse(element.GetModulus()));
#else
	ans *= (IntType(cycloOrder).ModInverse(element.GetModulus()));
#endif

	return ans;
}

template<typename IntType, typename VecType>
void NumberTheoreticTransform<IntType,VecType>::SetElement(const VecType &element) {
	m_element = &element;
}

template<typename IntType, typename VecType>
void NumberTheoreticTransform<IntType,VecType>::Destroy() {
	if( m_element != NULL ) delete m_element;
	m_element = NULL;
}


template<typename IntType, typename VecType>
ChineseRemainderTransform<IntType,VecType>& ChineseRemainderTransform<IntType,VecType>::GetInstance() {
	if (m_onlyInstance == NULL) {
		m_onlyInstance = new ChineseRemainderTransform<IntType,VecType>();
	}

	return *m_onlyInstance;
}

//template<typename IntType, typename VecType>
//ChineseRemainderTransformFTT<IntType,VecType>& ChineseRemainderTransformFTT<IntType,VecType>::GetInstance() {
//	if (m_onlyInstance == NULL) {
//		m_onlyInstance = new ChineseRemainderTransformFTT<IntType,VecType>();
//	}
//
//	return *m_onlyInstance;
//}


//main CRT Transform - uses iterative FFT as a subroutine
//includes precomputation of twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransform<IntType,VecType>::ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {

#pragma omp critical
	if (m_rootOfUnityTable == NULL) {
		m_rootOfUnityTable = new VecType(CycloOrder + 1);  //We may be able to change length to CycloOrder/2
		IntType x(IntType::ONE);
		for (usint i = 0; i<CycloOrder / 2; i++) {
			m_rootOfUnityTable->SetValAtIndex(i, x);
			m_rootOfUnityTable->SetValAtIndex(i + CycloOrder / 2, element.GetModulus() - x);
			x = x.ModMul(rootOfUnity, element.GetModulus());
		}

		m_rootOfUnityTable->SetValAtIndex(CycloOrder, IntType::ONE);

	}

	if (!IsPowerOfTwo(CycloOrder)) {
		std::cout << "Error in the FFT operation\n\n";
		exit(-10);
	}

	VecType OpFFT;
	VecType InputToFFT = ZeroPadForward(element, CycloOrder);

	if (!IsPowerOfTwo(element.GetLength())) {
		std::cout << "Input to FFT is not a power of two\n ERROR BEFORE FFT\n";
		OpFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(InputToFFT, *m_rootOfUnityTable, CycloOrder);
	}
	else {

		//auto start = std::chrono::steady_clock::now();

		OpFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(InputToFFT, *m_rootOfUnityTable, CycloOrder);

		/*auto end = std::chrono::steady_clock::now();

			auto diff = end - start;

			std::cout << std::chrono::duration <double, std::milli> (diff).count() << " ms" << std::endl;
			system("pause");*/
	}

	VecType ans(CycloOrder / 2);

	for (usint i = 0; i<CycloOrder / 2; i++)
		ans.SetValAtIndex(i, OpFFT.GetValAtIndex(2 * i + 1));

	ans.SetModulus(OpFFT.GetModulus());

	return ans;
}

//main CRT Transform - uses iterative FFT as a subroutine
//includes precomputation of inverse twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransform<IntType,VecType>::InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {

	IntType rootOfUnityInverse = rootOfUnity.ModInverse(element.GetModulus());

	if (!IsPowerOfTwo(CycloOrder)) {
		std::cout << "Error in the FFT operation\n\n";
		exit(-10);
	}

#pragma omp critical
	if (m_rootOfUnityInverseTable == NULL) {
		m_rootOfUnityInverseTable = new VecType(CycloOrder + 1);
		IntType x(IntType::ONE);
		for (usint i = 0; i<CycloOrder / 2; i++) {
			m_rootOfUnityInverseTable->SetValAtIndex(i, x);
			m_rootOfUnityInverseTable->SetValAtIndex(i + CycloOrder / 2, element.GetModulus() - x);
			x = x.ModMul(rootOfUnityInverse, element.GetModulus());
		}

		m_rootOfUnityInverseTable->SetValAtIndex(CycloOrder, IntType::ONE);

	}

	VecType OpIFFT;
	VecType InputToFFT = ZeroPadInverse(element, CycloOrder);

	if (!IsPowerOfTwo(element.GetLength())) {
		std::cout << "Input to IFFT is not a power of two\n ERROR BEFORE FFT\n";
		//HERE IS WHERE WE NEED ADD additional table of modinverse etc.
		OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(InputToFFT, *m_rootOfUnityInverseTable, CycloOrder);
	}
	else {
		OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(InputToFFT, *m_rootOfUnityInverseTable, CycloOrder);
	}

	VecType ans(CycloOrder / 2);
	//TODO:: can this be done quicker?
	for (usint i = 0; i<CycloOrder / 2; i++)
		ans.SetValAtIndex(i, (OpIFFT).GetValAtIndex(i).ModMul(IntType::TWO, (OpIFFT).GetModulus()));

	ans.SetModulus(OpIFFT.GetModulus());

	return ans;
}

//main Forward CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransformFTT<IntType,VecType>::ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {
	std::string errMsg;
	if (rootOfUnity == IntType::ONE || rootOfUnity == IntType::ZERO) {
		errMsg = "Root of unity cannot be zero or one to perform a forward transform";
		throw std::logic_error(errMsg);
	}
	if (!IsPowerOfTwo(CycloOrder)) {
		errMsg = "cyclotomic order must be a power of 2 to perform a forward transform";
		throw std::logic_error(errMsg);
	}

	//YSP mu is not needed for native data types
#if MATHBACKEND > 5
	IntType mu(IntType::ONE);
#else
	//Precompute the Barrett mu parameter
	IntType temp(IntType::ONE);
	temp <<= 2 * element.GetModulus().GetMSB() + 3;
	IntType mu = temp.DividedBy(element.GetModulus());
#endif

	const VecType *rootOfUnityTable = NULL;

	// check to see if the modulus is in the table, and add it if it isn't
#pragma omp critical
	{
		bool recompute = false;
		auto mSearch = m_rootOfUnityTableByModulus.find(element.GetModulus());

		if( mSearch != m_rootOfUnityTableByModulus.end() ) {
			// i found it... make sure it's kosher
			if( mSearch->second.GetLength() == 0 || mSearch->second.GetValAtIndex(1) != rootOfUnity ) {
				recompute = true;
			}
			else
				rootOfUnityTable = &mSearch->second;
		}

		if( mSearch == m_rootOfUnityTableByModulus.end() || recompute ){
			VecType rTable(CycloOrder / 2);
			IntType modulus(element.GetModulus());
			IntType x(IntType::ONE);

			for (usint i = 0; i<CycloOrder / 2; i++) {
				rTable.SetValAtIndex(i, x);
				x = x.ModBarrettMul(rootOfUnity, modulus, mu);
			}

			rootOfUnityTable = &(m_rootOfUnityTableByModulus[modulus] = std::move(rTable));
		}
	}

	VecType OpFFT;
	VecType InputToFFT(element);

	usint ringDimensionFactor = rootOfUnityTable->GetLength() / (CycloOrder / 2);

	//Fermat Theoretic Transform (FTT)
	for (usint i = 0; i<CycloOrder / 2; i++)
		InputToFFT.SetValAtIndex(i, element.GetValAtIndex(i).ModBarrettMul(rootOfUnityTable->GetValAtIndex(i*ringDimensionFactor), element.GetModulus(), mu));

	OpFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(InputToFFT, *rootOfUnityTable, CycloOrder / 2);

	return OpFFT;
}

//main Inverse CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of inverse twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransformFTT<IntType,VecType>::InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {
	std::string errMsg;
	if (rootOfUnity == IntType::ONE || rootOfUnity == IntType::ZERO) {
		errMsg = "Root of unity cannot be zero or one to perform an inverse transform";
		throw std::logic_error(errMsg);
	}
	if (!IsPowerOfTwo(CycloOrder)) {
		errMsg = "cyclotomic order must be a power of 2 to perform an inverse transform";
		throw std::logic_error(errMsg);
	}

	//YSP mu is not needed for native data types
#if MATHBACKEND > 5
	IntType mu(IntType::ONE);
#else
	//Pre-compute mu for Barrett function
	IntType temp(IntType::ONE);
	temp <<= 2 * element.GetModulus().GetMSB() + 3;
	IntType mu = temp.DividedBy(element.GetModulus());
#endif

	const VecType *rootOfUnityITable = NULL;

	IntType rootofUnityInverse;

	//TODO: is there a reason this isn't checked oly initially when the table is made? 
	try {
		rootofUnityInverse = rootOfUnity.ModInverse(element.GetModulus());
	} catch ( std::exception& e ) {
		errMsg = std::string(e.what()) + ": rootOfUnity " + rootOfUnity.ToString() + " has no inverse";
		throw std::logic_error(errMsg);
	}

	// check to see if the modulus is in the table
#pragma omp critical
	{
		bool recompute = false;
		auto mSearch = m_rootOfUnityInverseTableByModulus.find(element.GetModulus());

		if( mSearch != m_rootOfUnityInverseTableByModulus.end() ) {
			// i found it... make sure it's kosher
			if( mSearch->second.GetLength() == 0 || mSearch->second.GetValAtIndex(1) != rootofUnityInverse ) {
				recompute = true;
			}
			else
				rootOfUnityITable = &mSearch->second;
		}

		if( mSearch == m_rootOfUnityInverseTableByModulus.end() || recompute ) {
			VecType TableI(CycloOrder / 2);

			IntType x(IntType::ONE);

			for (usint i = 0; i<CycloOrder / 2; i++) {
				TableI.SetValAtIndex(i, x);
				x = x.ModBarrettMul(rootofUnityInverse, element.GetModulus(), mu);
			}

			rootOfUnityITable = &(m_rootOfUnityInverseTableByModulus[element.GetModulus()] = std::move(TableI));
		}
	}

	VecType OpIFFT;
	OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(element, *rootOfUnityITable, CycloOrder / 2);

	usint ringDimensionFactor = rootOfUnityITable->GetLength() / (CycloOrder / 2);

	VecType rInvTable(*rootOfUnityITable);
	for (usint i = 0; i<CycloOrder / 2; i++)
		OpIFFT.SetValAtIndex(i, OpIFFT.GetValAtIndex(i).ModBarrettMul(rInvTable.GetValAtIndex(i*ringDimensionFactor), element.GetModulus(), mu));

	return OpIFFT;
}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType &modulus) {

	//YSP mu is not needed for native data types
#if MATHBACKEND > 5
	IntType mu(IntType::ONE);
#else
	//Precompute the Barrett mu parameter
	IntType temp(IntType::ONE);
	temp <<= 2 * modulus.GetMSB() + 3;
	IntType mu = temp.DividedBy(modulus);
#endif

	IntType x(IntType::ONE);


	VecType *rootOfUnityTableCheck = NULL;
	rootOfUnityTableCheck = &m_rootOfUnityTableByModulus[modulus];
	//Precomputes twiddle factor omega and FTT parameter phi for Forward Transform
	if (rootOfUnityTableCheck->GetLength() == 0) {
		VecType Table(CycloOrder / 2);


		for (usint i = 0; i<CycloOrder / 2; i++) {
			Table.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnity, modulus, mu);
		}

		this->m_rootOfUnityTableByModulus[modulus] = std::move(Table);
	}

	//Precomputes twiddle factor omega and FTT parameter phi for Inverse Transform
	VecType  *rootOfUnityInverseTableCheck = &m_rootOfUnityInverseTableByModulus[modulus];
	if (rootOfUnityInverseTableCheck->GetLength() == 0) {
		VecType TableI(CycloOrder / 2);
		IntType rootOfUnityInverse = rootOfUnity.ModInverse(modulus);

		x = IntType::ONE;

		for (usint i = 0; i<CycloOrder / 2; i++) {
			TableI.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnityInverse, modulus, mu);
		}

		this->m_rootOfUnityInverseTableByModulus[modulus] = std::move(TableI);

	}

}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::PreCompute(std::vector<IntType> &rootOfUnity, const usint CycloOrder, std::vector<IntType> &moduliiChain) {

	usint numOfRootU = rootOfUnity.size();
	usint numModulii = moduliiChain.size();

	if (numOfRootU != numModulii) {
		throw std::logic_error("size of root of unity and size of moduli chain not of same size");
		system("pause");
	}

	for (usint i = numOfRootU; i<numOfRootU; ++i) {

		IntType currentRoot(rootOfUnity[i]);
		IntType currentMod(moduliiChain[i]);

		//mu is not needed for native data types
#if MATHBACKEND > 5
		IntType mu(IntType::ONE);
#else
		//Precompute the Barrett mu parameter
		IntType temp(IntType::ONE);
		temp <<= 2 * currentMod.GetMSB() + 3;
		IntType mu = temp.DividedBy(currentMod);
#endif

		if (this->m_rootOfUnityTableByModulus[moduliiChain[i]].GetLength() != 0)
			continue;



		IntType x(IntType::ONE);


		//computation of root of unity table
		VecType rTable(CycloOrder / 2);


		for (usint i = 0; i<CycloOrder / 2; i++) {
			rTable.SetValAtIndex(i, x);
			x = x.ModBarrettMul(currentRoot, currentMod, mu);
		}

		this->m_rootOfUnityTableByModulus[currentMod] = std::move(rTable);

		//computation of root of unity inverse table
		x = IntType::ONE;

		IntType rootOfUnityInverse = currentRoot.ModInverse(currentMod);

		VecType rTableI(CycloOrder / 2);


		for (usint i = 0; i<CycloOrder / 2; i++) {
			rTableI.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnityInverse, currentMod, mu);
		}

		this->m_rootOfUnityInverseTableByModulus[currentMod] = std::move(rTableI);


	}


}

template<typename IntType, typename VecType>
void ChineseRemainderTransform<IntType,VecType>::Destroy() {
	if( m_rootOfUnityTable ) delete m_rootOfUnityTable;
	if( m_rootOfUnityInverseTable ) delete m_rootOfUnityInverseTable;
}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::Destroy() {
	if( m_onlyInstance != NULL ) delete m_onlyInstance;
	m_onlyInstance = NULL;
}
	
	void DiscreteFourierTransform::Destroy() {
		if (rootOfUnityTable) {
			delete rootOfUnityTable;
			rootOfUnityTable = 0;
		}
		if (m_onlyInstance) {
			delete m_onlyInstance; 
			m_onlyInstance = 0;
		}
	}
	void DiscreteFourierTransform::PreComputeTable(uint32_t s) {
		size = s;
		if (rootOfUnityTable) {
			delete rootOfUnityTable;
			rootOfUnityTable = 0;
		}
		rootOfUnityTable = new std::complex<double>[s];
		for (int j = 0;j < s;j++) {
			rootOfUnityTable[j] = std::polar(1.0, -2 * M_PI * j / s);
		}
	}

	std::vector<std::complex<double>> DiscreteFourierTransform::FFTForwardTransform(std::vector<std::complex<double>> & A) {
		int m = A.size();
		std::vector<std::complex<double>> B(A);
		int levels = floor(log2(m));

		static int cachedM;
		static std::vector<double> cosTable;
		static std::vector<double> sinTable;

		if( m != cachedM ) {
			cachedM = m;
			sinTable.resize(m/2);
			cosTable.resize(m/2);
			for (int i = 0; i < m / 2; i++) {
				cosTable[i] = cos(2 * M_PI * i / m);
				sinTable[i] = sin(2 * M_PI * i / m);
			}
		}

		// Bit-reversed addressing permutation
		for (int i = 0; i < m; i++) {
			int j = ReverseBits(i,32) >> (32-levels);
			if (j > i) {
				double temp = B[i].real();
				B[i].real( B[j].real() );
				B[j].real( temp );
				temp = B[i].imag();
				B[i].imag( B[j].imag() );
				B[j].imag( temp );
			}
		}

		// Cooley-Tukey decimation-in-time radix-2 FFT
		for (int size = 2; size <= m; size *= 2) {
			int halfsize = size / 2;
			int tablestep = m / size;
			for (int i = 0; i < m; i += size) {
				for (int j = i, k = 0; j < i + halfsize; j++, k += tablestep) {
					double tpre =  B[j+halfsize].real() * cosTable[k] + B[j+halfsize].imag() * sinTable[k];
					double tpim = -B[j+halfsize].real() * sinTable[k] + B[j+halfsize].imag() * cosTable[k];
					B[j + halfsize].real( B[j].real() - tpre );
					B[j + halfsize].imag( B[j].imag() - tpim );
					B[j].real( B[j].real() + tpre );
					B[j].imag( B[j].imag() + tpim );
				}
			}
			if (size == m)  // Prevent overflow in 'size *= 2'
				break;
		}

		return B;
	}

	std::vector<std::complex<double>> DiscreteFourierTransform::FFTInverseTransform(std::vector<std::complex<double>> & A) {

		std::vector<std::complex<double>> result = DiscreteFourierTransform::FFTForwardTransform(A);
		double n = result.size() / 2;
		for (int i = 0;i < n;i++) {
			result[i] = std::complex<double>(result[i].real() / n, result[i].imag() / n);
		}
		return result;
	}
	std::vector<std::complex<double>> DiscreteFourierTransform::ForwardTransform(std::vector<std::complex<double>> A) {
		int n = A.size();
		for (int i = 0;i < n;i++) {
			A.push_back(0);
		}
		if (rootOfUnityTable == NULL) {
			PreComputeTable(2 * n);
		}
		std::vector<std::complex<double>> dft = FFTForwardTransform(A);
		std::vector<std::complex<double>> dftRemainder;
		for (int i = dft.size() - 1;i > 0;i--) {
			if (i % 2 != 0) {
				dftRemainder.push_back(dft.at(i));
			}
		}
		return dftRemainder;
	}
	std::vector<std::complex<double>> DiscreteFourierTransform::InverseTransform(std::vector<std::complex<double>> A) {
		int n = A.size();
		std::vector<std::complex<double>> dft;
		for (int i = 0;i < n;i++) {
			dft.push_back(0);
			dft.push_back(A.at(i));
		}
		std::vector<std::complex<double>> invDft = FFTInverseTransform(dft);
		std::vector<std::complex<double>> invDftRemainder;
		for (int i = 0;i<invDft.size() / 2;i++) {
			invDftRemainder.push_back(invDft.at(i));
		}
		return invDftRemainder;
	}

	DiscreteFourierTransform& DiscreteFourierTransform::GetInstance() {
		if (m_onlyInstance == NULL) {
			m_onlyInstance = new DiscreteFourierTransform();//lazy instantiation
		}
		return *m_onlyInstance;
	}

	template<typename IntType, typename VecType>
	BluesteinFFT<IntType, VecType>& BluesteinFFT<IntType, VecType>::GetInstance() {
		if (m_onlyInstance == NULL) {
			m_onlyInstance = new BluesteinFFT<IntType, VecType>();//lazy instantiation
		}
		return *m_onlyInstance;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::PreComputeNTTModulus(usint cycloOrder, const IntType &modulus) {
		usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));
		const auto newMod = FindPrimeModulus<IntType>(nttDim, log2(nttDim) + 2 * modulus.GetMSB());
		m_NTTModulus[modulus] = newMod;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::SetPreComputedNTTModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod) {
		m_NTTModulus[modulus] = nttMod;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::PreComputeRootTableForNTT(usint cycloOrder, const IntType &modulus) {
		usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));
		const auto &nttMod = m_NTTModulus[modulus];

		auto root = RootOfUnity(nttDim, nttMod);

		auto rootInv = root.ModInverse(nttMod);

		VecType rootTable(nttDim/2, nttMod);
		VecType rootTableInverse(nttDim/2, nttMod);

		IntType x(IntType::ONE);
		for (usint i = 0; i<nttDim / 2; i++) {
			rootTable.SetValAtIndex(i, x);
			x = x.ModMul(root, nttMod);
		}

		x = (IntType::ONE);
		for (usint i = 0; i<nttDim / 2; i++) {
			rootTableInverse.SetValAtIndex(i, x);
			x = x.ModMul(rootInv, nttMod);
		}

		m_rootOfUnityTableByModulus[nttMod] = rootTable;
		m_rootOfUnityInverseTableByModulus[nttMod] = rootTableInverse;

	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::SetRootTableForNTT(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod, const IntType &nttRoot) {
		usint nttDim = pow(2, ceil(log2(2 * cyclotoOrder - 1)));

		IntType root(nttRoot);

		auto rootInv = root.ModInverse(nttMod);

		VecType rootTable(nttDim / 2, nttMod);
		VecType rootTableInverse(nttDim / 2, nttMod);

		IntType x(IntType::ONE);
		for (usint i = 0; i<nttDim / 2; i++) {
			rootTable.SetValAtIndex(i, x);
			//rootTable.SetValAtIndex(i + nttDim / 2, nttMod - x);
			x = x.ModMul(root, nttMod);
		}

		//rootTable.SetValAtIndex(nttDim, IntType::ONE);

		x = (IntType::ONE);
		for (usint i = 0; i<nttDim / 2; i++) {
			rootTableInverse.SetValAtIndex(i, x);
			//rootTableInverse.SetValAtIndex(i + nttDim / 2, nttMod - x);
			x = x.ModMul(rootInv, nttMod);
		}
		//rootTableInverse.SetValAtIndex(nttDim, IntType::ONE);

		m_rootOfUnityTableByModulus[nttMod] = rootTable;
		m_rootOfUnityInverseTableByModulus[nttMod] = rootTableInverse;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::PreComputePowers(usint cycloOrder, const IntType &modulus, const IntType &root) {

		VecType powers(cycloOrder, modulus);
		powers.SetValAtIndex(0, IntType::ONE);
		for (usint i = 1; i <cycloOrder; i++) {
			auto iSqr = (i*i) % (2 * cycloOrder);
			auto val = root.ModExp(IntType(iSqr), modulus);
			powers.SetValAtIndex(i, val);
		}
		m_powersTableByRoot[root] = std::move(powers);

	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder) {
		if (element.GetLength() != cycloOrder) {
			throw std::runtime_error("expected size of element vector should be equal to cyclotomic order");
		}

		const auto &modulus = element.GetModulus();

		const auto &nttModulus = m_NTTModulus[modulus]; //assumes nttModulus is precomputed

		const auto &rootTable = m_rootOfUnityTableByModulus[nttModulus]; //assumes rootTable is precomputed

		const auto &rootTableInverse = m_rootOfUnityInverseTableByModulus[nttModulus]; //assumes rootTableInverse is precomputed

		const VecType &powers = m_powersTableByRoot[root];

		/*VecType &powers(cycloOrder, modulus);
		powers.SetValAtIndex(0, IntType::ONE);
		for (usint i = 1; i <cycloOrder; i++) {
			auto iSqr = (i*i) % (2 * cycloOrder);
			auto val = root.ModExp(IntType(iSqr), modulus);
			powers.SetValAtIndex(i, val);
		}*/

		VecType x(element*powers);

		//usint k2 = 2^NextPowerOfTwo(2* cycloOrder-1);
		usint k2 = pow(2, ceil(log2(2 * cycloOrder - 1)));

		auto rootInv = root.ModInverse(modulus);
		VecType b(2 * cycloOrder - 1, modulus);
		b.SetValAtIndex(cycloOrder - 1, IntType::ONE);
		for (usint i = 1; i < cycloOrder; i++) {
			auto iSqr = (i*i) % (2 * cycloOrder);
			auto val = rootInv.ModExp(IntType(iSqr), modulus);
			b.SetValAtIndex(cycloOrder - 1 + i, val);
			b.SetValAtIndex(cycloOrder - 1 - i, val);
		}

		auto Ra = PadZeros(x, k2);
		auto Rb = PadZeros(b, k2);

		Ra.SetModulus(nttModulus);
		Rb.SetModulus(nttModulus);

		//std::cout << rootTable.GetValAtIndex(1) << std::endl;
		//std::cout << nttModulus << std::endl;

		//std::cout << Ra << std::endl;
		//std::cout << Rb << std::endl;

		auto RA = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(Ra, rootTable, k2);
		auto RB = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(Rb, rootTable, k2);

		auto RC = RA*RB;
		auto Rc = NumberTheoreticTransform<IntType, VecType>::GetInstance().InverseTransformIterative(RC, rootTableInverse, k2);

		//auto Rc = PolynomialMultiplication(Ra, Rb);	

		auto resizeRc = Resize(Rc, cycloOrder - 1, 2 * (cycloOrder - 1));

		resizeRc.SetModulus(modulus);

		auto result = resizeRc*powers;

		return result;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::SetElement(const VecType &element) {

	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::PadZeros(const VecType &a, const usint finalSize) {
		usint s = a.GetLength();
		VecType result(finalSize, a.GetModulus());

		for (usint i = 0; i < s; i++) {
			result.SetValAtIndex(i, a.GetValAtIndex(i));
		}

		for (usint i = a.GetLength(); i < finalSize; i++) {
			result.SetValAtIndex(i, IntType::ZERO);
		}

		return result;
	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::Resize(const VecType &a, usint  lo, usint hi) {
		VecType result(hi - lo + 1, a.GetModulus());

		for (usint i = lo, j = 0; i <= hi; i++, j++) {
			result.SetValAtIndex(j, a.GetValAtIndex(i));
		}

		return result;
	}

	template<typename IntType, typename VecType>
	ChineseRemainderTransformArb<IntType, VecType>& ChineseRemainderTransformArb<IntType, VecType>::GetInstance() {
		if (m_onlyInstance == NULL) {
			m_onlyInstance = new ChineseRemainderTransformArb<IntType, VecType>();//lazy instantiation
		}
		return *m_onlyInstance;
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::SetCylotomicPolynomial(const VecType &poly, const IntType &mod) {
		m_cyclotomicPolyMap[mod] = poly;
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::PreCompute(const usint cyclotoOrder, const IntType &modulus) {

		BluesteinFFT<IntType, VecType>::GetInstance().PreComputeNTTModulus(cyclotoOrder, modulus);

		BluesteinFFT<IntType, VecType>::GetInstance().PreComputeRootTableForNTT(cyclotoOrder, modulus);

	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::SetPreComputedNTTModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod, const IntType &nttRoot) {

		BluesteinFFT<IntType, VecType>::GetInstance().SetPreComputedNTTModulus(cyclotoOrder, modulus, nttMod);

		BluesteinFFT<IntType, VecType>::GetInstance().SetRootTableForNTT(cyclotoOrder, modulus, nttMod, nttRoot);
	}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::ForwardTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot, const usint cycloOrder) {

		usint n = GetTotient(cycloOrder);
		if (element.GetLength() != n) {
			throw std::runtime_error("element size should be equal to phim");
		}

		const auto &modulus = element.GetModulus();
		VecType inputToBluestein(cycloOrder, modulus);
		auto tList = GetTotientList(cycloOrder);

		for (usint i = 0; i < n; i++) {
			inputToBluestein.SetValAtIndex(i, element.GetValAtIndex(i));
		}

		//precompute bigroot of unity and inverse root of unity table if it's not yet computed.
		if (BluesteinFFT<IntType, VecType>::GetInstance().m_rootOfUnityTableByModulus[bigMod].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().SetPreComputedNTTModulus(cycloOrder,modulus,bigMod);
			BluesteinFFT<IntType, VecType>::GetInstance().SetRootTableForNTT(cycloOrder,modulus,bigMod,bigRoot);
		}

		//precompute powers table 
		if (BluesteinFFT<IntType, VecType>::GetInstance().m_powersTableByRoot[root].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputePowers(cycloOrder, modulus, root);
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputePowers(cycloOrder, modulus, root.ModInverse(modulus));
		}

		auto outputBluestein = BluesteinFFT<IntType, VecType>::GetInstance().ForwardTransform(inputToBluestein, root, cycloOrder);

		VecType output(n, modulus);

		for (usint i = 0; i < n; i++) {
			output.SetValAtIndex(i, outputBluestein.GetValAtIndex(tList[i]));
		}

		return output;

	}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::InverseTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot, const usint cycloOrder) {
		
		usint n = GetTotient(cycloOrder);

		if (element.GetLength() != n) {
			throw std::runtime_error("element size should be equal to phim");
		}

		const auto &modulus = element.GetModulus();
		VecType inputToBluestein(cycloOrder, modulus);
		auto rootInverse(root.ModInverse(modulus));
		auto tList = GetTotientList(cycloOrder);
		usint i = 0;
		for (auto &coprime : tList) {
			inputToBluestein.SetValAtIndex(coprime, element.GetValAtIndex(i++));
		}

		//precompute bigroot of unity and inverse root of unity table if it's not yet computed.
		if (BluesteinFFT<IntType, VecType>::GetInstance().m_rootOfUnityTableByModulus[bigMod].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().SetPreComputedNTTModulus(cycloOrder, modulus, bigMod);
			BluesteinFFT<IntType, VecType>::GetInstance().SetRootTableForNTT(cycloOrder, modulus, bigMod, bigRoot);
		}

		//precompute powers table 
		if (BluesteinFFT<IntType, VecType>::GetInstance().m_powersTableByRoot[root].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputePowers(cycloOrder, modulus, root);
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputePowers(cycloOrder, modulus, rootInverse);
		}

		auto outputBluestein = BluesteinFFT<IntType, VecType>::GetInstance().ForwardTransform(inputToBluestein, rootInverse, cycloOrder);

		auto cyclotomicInverse = (IntType(cycloOrder)).ModInverse(modulus);

		outputBluestein = outputBluestein*cyclotomicInverse;

		auto output = PolyMod(outputBluestein, this->m_cyclotomicPolyMap[modulus], modulus);

		return output;
	}



	template class ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>;
	template class NumberTheoreticTransform<BigBinaryInteger,BigBinaryVector>;
	template class ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>;
	template class BluesteinFFT<BigBinaryInteger, BigBinaryVector>;
	extern template  BigBinaryVector PolyMod(const BigBinaryVector &dividend, const BigBinaryVector &divisor, const BigBinaryInteger &modulus);

// FIXME the MATH_BACKEND check is a hack and needs to go away
#if MATHBACKEND != 7
#ifndef NO_MATHBACKEND_7
	template class ChineseRemainderTransformFTT<native64::BigBinaryInteger,native64::BigBinaryVector>;
	template class NumberTheoreticTransform<native64::BigBinaryInteger,native64::BigBinaryVector>;
	template class ChineseRemainderTransformArb<native64::BigBinaryInteger, native64::BigBinaryVector>;
	template class BluesteinFFT<native64::BigBinaryInteger, native64::BigBinaryVector>;
	extern template  native64::BigBinaryVector PolyMod(const native64::BigBinaryVector &dividend, const native64::BigBinaryVector &divisor, const native64::BigBinaryInteger &modulus);

#endif
#endif

}//namespace ends here
