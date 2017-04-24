/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 * 
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 * This file contains the linear transform interface functionality.
 */

#ifndef LBCRYPTO_MATH_TRANSFRM_H
#define LBCRYPTO_MATH_TRANSFRM_H


#include "backend.h"
#include "nbtheory.h"
#include "../utils/utilities.h"
#include <chrono>
#include <complex>
#include <time.h>
#include <map>
#include <fstream>
#include <thread>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Generic transform class.
 */
class Transform
{
};

/**
 * @brief Generic linear transform class.
 */
template<typename IntType, typename VecType>
class LinearTransform : public Transform
{
public:
	/**
	 * Virtual forward transform.
	 *
	 * @param &element is the element to perform the transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	virtual VecType ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) = 0;

	/**
	 * Virtual inverse transform.
	 *
	 * @param &element is the element to perform the inverse transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the inverse transform.	  	  
	 */
	virtual VecType InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) = 0;
	//static VecType& ZeroPadd(const VecType&,usint);
};

/**
 * @brief Number Theoretic Transform implemetation 
 */
template<typename IntType, typename VecType>
class NumberTheoreticTransform 
{
public:
	/**
	 * Get instance to return this object.
	 *
	 * @return is this object.	  	  
	 */
	static NumberTheoreticTransform& GetInstance();

	/**
	 * Forward transform.
	 *
	 * @param element is the element to perform the transform on.
	 * @param rootOfUnityTable the root of unity table.
	 * @param cycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	VecType ForwardTransformIterative(const VecType& element, const VecType& rootOfUnityTable,const usint cycloOrder) ;

	/**
	 * Inverse transform.
	 *
	 * @param element is the element to perform the transform on.
	 * @param rootOfUnityInverseTable the root of unity table.
	 * @param cycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	VecType InverseTransformIterative(const VecType& element,const VecType& rootOfUnityInverseTable,const usint cycloOrder) ;

	/**
	 * Set the ring element.
	 *
	 * @param &element is the element to set.	  	  
	 */
	void SetElement(const VecType &element);

	/**
	 * Destructor.	 
	 */
	void Destroy();
private:
	static NumberTheoreticTransform *m_onlyInstance;
	NumberTheoreticTransform(): m_element(0) {}
	~NumberTheoreticTransform(){}
	NumberTheoreticTransform(const NumberTheoreticTransform&): m_element(0) {}
//	NumberTheoreticTransform& operator=(NumberTheoreticTransform const&) {}
	const VecType *m_element;
};

/**
 * @brief Chinese Remainder Transform implemetation.  This is a refined, higher performance implementation.
 */
template<typename IntType, typename VecType>
class ChineseRemainderTransform : public LinearTransform<IntType,VecType>
{
public:
	/**
	 * Get instance to return this object.
	 *
	 * @return is this object.	  	  
	 */
	static ChineseRemainderTransform& GetInstance();

	/**
	 * Virtual forward transform.
	 *
	 * @param &element is the element to perform the transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	VecType ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) ;

	/**
	 * Virtual inverse transform.
	 *
	 * @param &element is the element to perform the inverse transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the inverse transform.	  	  
	 */
	VecType InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) ;

	/**
	 * Destructor.	 
	 */
	void Destroy();
private:
	static ChineseRemainderTransform *m_onlyInstance;
	static VecType *m_rootOfUnityTable;
	static VecType *m_rootOfUnityInverseTable;
	ChineseRemainderTransform(){}
	~ChineseRemainderTransform(){}
	ChineseRemainderTransform(const ChineseRemainderTransform&){}
	ChineseRemainderTransform& operator=(ChineseRemainderTransform const&){};
};

/**
 * @brief Golden Chinese Remainder Transform FFT implemetation.
 */
template<typename IntType, typename VecType>
class ChineseRemainderTransformFTT : public LinearTransform<IntType,VecType>
{
public:
	/**
	 * Get instance to return this object.
	 *
	 * @return is this object.	  	  
	 */
	static ChineseRemainderTransformFTT& GetInstance() {
		if (m_onlyInstance == NULL) {
			m_onlyInstance = new ChineseRemainderTransformFTT<IntType,VecType>();
		}

		return *m_onlyInstance;
	}

	/**
	 * Virtual forward transform.
	 *
	 * @param &element is the element to perform the transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	VecType ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) ;

	/**
	 * Virtual inverse transform.
	 *
	 * @param &element is the element to perform the inverse transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the inverse transform.	  	  
	 */
	VecType InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) ;

	/**
	* Precomputation of root of unity tables.
	*
	* @param rootOfUnity the root of unity.
	* @param CycloOrder is the cyclotomic order.
	* @param modulus is the modulus
	*/
	void PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType &modulus);

	/**
	* Precomputation of root of unity tables.
	*
	* @param &rootOfUnity the root of unity.
	* @param CycloOrder is the cyclotomic order.
	* @param &moduliiChain is the modulus
	*/
	void PreCompute(std::vector<IntType> &rootOfUnity, const usint CycloOrder, std::vector<IntType> &moduliiChain);
	/**
	 * Destructor.	 
	 */
	void Destroy();
	
private:
	static ChineseRemainderTransformFTT *m_onlyInstance;
	static std::map<IntType,VecType> m_rootOfUnityTableByModulus;
	static std::map<IntType,VecType> m_rootOfUnityInverseTableByModulus;
	//static VecType *m_rootOfUnityTable;
	
	//static VecType *m_rootOfUnityInverseTable;
	//static VecType *m_phiTable;
	//static VecType *m_phiInverseTable;
	ChineseRemainderTransformFTT(){}
	~ChineseRemainderTransformFTT(){}
	ChineseRemainderTransformFTT(const ChineseRemainderTransformFTT<IntType, VecType>&) {}
	//ChineseRemainderTransformFTT& operator=(ChineseRemainderTransformFTT<IntType,VecType> const&){};
};

/**
* @brief Discrete Fourier Transform FFT implemetation.
*/
class DiscreteFourierTransform
{
public:
	/**
	* Virtual FFT forward transform.
	*
	* @param A is the element to perform the transform on.
	* @return is the output result of the transform.
	*/
	std::vector<std::complex<double>> FFTForwardTransform(std::vector<std::complex<double>>& A);

	/**
	* Virtual FFT inverse transform.
	*
	* @param A is the element to perform the inverse transform on.
	* @return is the output result of the inverse transform.
	*/
	std::vector<std::complex<double>> FFTInverseTransform(std::vector<std::complex<double>>& A);
	
	/**
	* Virtual forward transform.
	*
	* @param A is the element to perform the transform on.
	* @return is the output result of the transform.
	*/
	std::vector<std::complex<double>> ForwardTransform(std::vector<std::complex<double>> A);

	/**
	* Virtual inverse transform.
	*
	* @param A is the element to perform the inverse transform on.
	* @return is the output result of the inverse transform.
	*/
	std::vector<std::complex<double>> InverseTransform(std::vector<std::complex<double>> A);

	void Destroy();
	void PreComputeTable(uint32_t s);
	static DiscreteFourierTransform& GetInstance();

private:
	static DiscreteFourierTransform* m_onlyInstance;
	static std::complex<double>* rootOfUnityTable;
	uint32_t size;
};

/**
* @brief Bluestein Fast Fourier Transform implemetation
*/
template<typename IntType, typename VecType>
class BluesteinFFT {
public:
	/**
	* Get instance to return this object.
	*
	* @return is this object.
	*/
	static BluesteinFFT& GetInstance();

	/**
	* Forward transform.
	*
	* @param element is the element to perform the transform on.
	* @param rootOfUnityTable the root of unity table.
	* @param cycloOrder is the cyclotomic order.
	* @return is the output result of the transform.
	*/
	VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder);

	/**
	* Inverse transform.
	*
	* @param element is the element to perform the transform on.
	* @param rootOfUnityInverseTable the root of unity table.
	* @param cycloOrder is the cyclotomic order.
	* @return is the output result of the transform.
	*/
	VecType InverseTransform(const VecType& element, const VecType& rootOfUnityInverseTable, const usint cycloOrder);

	/**
	* Set the ring element.
	*
	* @param &element is the element to set.
	*/
	void SetElement(const VecType &element);

	VecType PadZeros(const VecType &a, const usint finalSize);

	VecType Resize(const VecType &a, usint  lo, usint hi);

	void PreComputeNTTModulus(usint cycloOrder, const std::vector<IntType> &modulii);

	void PreComputeNTTModulus(usint cycloOrder, const IntType &modulus);

	void PreComputeRootTableForNTT(usint cycloOrder, const IntType &modulus);

	/**
	* Destructor.
	*/
	void Destroy();

private:
	static std::map<IntType, VecType> m_rootOfUnityTableByModulus;
	static std::map<IntType, VecType> m_rootOfUnityInverseTableByModulus;
	static std::map<IntType, IntType> m_NTTModulus;
	static BluesteinFFT *m_onlyInstance;
	BluesteinFFT() : m_element(0) {}
	~BluesteinFFT() {}
	BluesteinFFT(const BluesteinFFT&) : m_element(0) {}
	const VecType *m_element;
	usint k2;

};

/**
* @brief Chinese Remainder Transform Arbitrary implemetation
*/
template<typename IntType, typename VecType>
class ChineseRemainderTransformArb {
public:
	/**
	* Get instance to return this object.
	*
	* @return is this object.
	*/
	static ChineseRemainderTransformArb& GetInstance();

	/**
	* Sets the cyclotomic polynomial.
	*
	*/
	static void SetCylotomicPolynomial(const VecType &poly, const IntType &mod);

	/**
	* Forward transform.
	*
	* @param element is the element to perform the transform on.
	* @param rootOfUnityTable the root of unity table.
	* @param cycloOrder is the cyclotomic order.
	* @return is the output result of the transform.
	*/
	VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder);

	/**
	* Inverse transform.
	*
	* @param element is the element to perform the transform on.
	* @param rootOfUnityInverseTable the root of unity table.
	* @param cycloOrder is the cyclotomic order.
	* @return is the output result of the transform.
	*/
	VecType InverseTransform(const VecType& element, const IntType& root, const usint cycloOrder);

	/**
	* Set the ring element.
	*
	* @param &element is the element to set.
	*/
	void SetElement(const VecType &element);

	VecType PadZeros(const VecType &a, const usint finalSize);

	/**
	* Destructor.
	*/
	void Destroy();

	void PreCompute(const usint cyclotoOrder, const IntType &modulus);
private:
	static ChineseRemainderTransformArb *m_onlyInstance;
	ChineseRemainderTransformArb() : m_element(0) {}
	~ChineseRemainderTransformArb() {}
	ChineseRemainderTransformArb(const ChineseRemainderTransformArb&) : m_element(0) {}
	const VecType *m_element;
	static std::map<IntType, VecType> m_cyclotomicPolyMap;
};

	

} // namespace lbcrypto ends

#endif
