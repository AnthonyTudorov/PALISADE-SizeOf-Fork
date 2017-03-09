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

template class ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>;
template class ChineseRemainderTransformFTT<native64::BigBinaryInteger,native64::BigBinaryVector>;

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
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityInverseTableByModulus;


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
	usint ringDimensionFactor = (rootOfUnityTable.GetLength()) / cycloOrder;

	//Precompute the Barrett mu parameter
	IntType temp(IntType::ONE);
	temp <<= 2 * element.GetModulus().GetMSB() + 3;
	IntType mu = temp.DividedBy(element.GetModulus());

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
						product = omega*result.GetValAtIndex(indexOdd);
						//omegaFactor = product.ModBarrett(element.GetModulus(),mu_arr);
						omegaFactor = product.ModBarrett(element.GetModulus(), mu);
					}

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

				}
				else
					result.SetValAtIndex(indexOdd, result.GetValAtIndex(indexEven));

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

	ans = ans.ModMul(IntType(cycloOrder).ModInverse(element.GetModulus()));

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

template<typename IntType, typename VecType>
ChineseRemainderTransformFTT<IntType,VecType>& ChineseRemainderTransformFTT<IntType,VecType>::GetInstance() {
	if (m_onlyInstance == NULL) {
		m_onlyInstance = new ChineseRemainderTransformFTT<IntType,VecType>();
	}

	return *m_onlyInstance;
}


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
		OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(InputToFFT, *m_rootOfUnityInverseTable, CycloOrder);
	}
	else {
		OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(InputToFFT, *m_rootOfUnityInverseTable, CycloOrder);
	}

	VecType ans(CycloOrder / 2);

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

	//Pre-compute mu for Barrett function
	IntType temp(IntType::ONE);
	temp <<= 2 * element.GetModulus().GetMSB() + 3;
	IntType mu = temp.DividedBy(element.GetModulus());

	VecType *rootOfUnityTable = NULL;

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

	//Pre-compute mu for Barrett function
	IntType temp(IntType::ONE);
	temp <<= 2 * element.GetModulus().GetMSB() + 3;
	IntType mu = temp.DividedBy(element.GetModulus());

	VecType *rootOfUnityITable = NULL;

	IntType rootofUnityInverse;

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

	//Pre-compute mu for Barrett function
	IntType temp(IntType::ONE);
	temp <<= 2 * modulus.GetMSB() + 3;
	IntType mu = temp.DividedBy(modulus);

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

		//Pre-compute mu for Barrett function
		IntType temp(IntType::ONE);
		temp <<= 2 * currentMod.GetMSB() + 3;
		IntType mu = temp.DividedBy(currentMod);

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


std::vector<std::complex<double>> DiscreteFourierTransform::FFTForwardTransform(std::vector<std::complex<double>> & A) {
	if (A.size()==1) {
		return A;
	}
	else {
		int m = A.size();
		std::vector<std::complex<double>> A_even(m/2);
		std::vector<std::complex<double>> A_odd(m/2);
		for (int i = 0;i<m;i++) {
			if (i % 2 == 0) {
				A_even[i / 2] = A[i];
			}
			else {
				A_odd[(i-1)/2] = A[i];
			}
		}
		std::vector<std::complex<double>> P_even = DiscreteFourierTransform::FFTForwardTransform(A_even);
		std::vector<std::complex<double>> P_odd = DiscreteFourierTransform::FFTForwardTransform(A_odd);
		std::vector<std::complex<double>> P(m,0);

		for (int j = 0;j<m / 2;j++) {
			std::complex<double> x = std::polar(1.0, -2 * M_PI * j / m) * P_odd[j];
			P[j] = P_even[j] + x ;
			P[j+m/2] = P_even[j] - x;
		}
		return P;
	}
}

std::vector<std::complex<double>> DiscreteFourierTransform::FFTInverseTransform(std::vector<std::complex<double>> & A) {

	std::vector<std::complex<double>> result = DiscreteFourierTransform::FFTForwardTransform(A);
	double n = result.size()/2;
	for(int i=0;i < n;i++) {
		result[i] = std::complex<double>(result[i].real() / n, result[i].imag() / n);
		//result[i] =std::complex<double>(result[i].real()/(2*n), result[i].imag()/(2*n));
	}
	return result;
}
std::vector<std::complex<double>> DiscreteFourierTransform::ForwardTransform(std::vector<std::complex<double>> A) {
	int n = A.size();
	for (int i = 0;i < n;i++) {
		A.push_back(0);
	}
	std::vector<std::complex<double>> dft = FFTForwardTransform(A);
	std::vector<std::complex<double>> dftRemainder;
	for (int i = dft.size() - 1;i > 0;i--) {
		if (i % 2 != 0) {
			dftRemainder.push_back(dft.at(i));
			//dftRemainder.push_back(std::complex<double>(2*dft.at(i).real(), 2 * dft.at(i).imag()));
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
	for (int i = 0;i<invDft.size()/2;i++) {
		invDftRemainder.push_back(invDft.at(i));
	}
	return invDftRemainder;
}

}//namespace ends here
