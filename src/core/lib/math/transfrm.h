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
	virtual BigBinaryVector ForwardTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity, const usint CycloOrder) = 0;

	/**
	 * Virtual inverse transform.
	 *
	 * @param &element is the element to perform the inverse transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the inverse transform.	  	  
	 */
	virtual BigBinaryVector InverseTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity, const usint CycloOrder) = 0;
	//static BigBinaryVector& ZeroPadd(const BigBinaryVector&,usint);
};

/**
 * @brief Number Theoretic Transform implemetation 
 */
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
	BigBinaryVector ForwardTransformIterative(const BigBinaryVector& element, const BigBinaryVector& rootOfUnityTable,const usint cycloOrder) ;

	/**
	 * Inverse transform.
	 *
	 * @param element is the element to perform the transform on.
	 * @param rootOfUnityInverseTable the root of unity table.
	 * @param cycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	BigBinaryVector InverseTransformIterative(const BigBinaryVector& element,const BigBinaryVector& rootOfUnityInverseTable,const usint cycloOrder) ;

	/**
	 * Set the ring element.
	 *
	 * @param &element is the element to set.	  	  
	 */
	void SetElement(const BigBinaryVector &element);

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
	const BigBinaryVector *m_element;
};

/**
 * @brief Chinese Remainder Transform implemetation.  This is a refined, higher performance implementation.
 */
class ChineseRemainderTransform : public LinearTransform
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
	BigBinaryVector ForwardTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity, const usint CycloOrder) ;

	/**
	 * Virtual inverse transform.
	 *
	 * @param &element is the element to perform the inverse transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the inverse transform.	  	  
	 */
	BigBinaryVector InverseTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity, const usint CycloOrder) ;

	/**
	 * Destructor.	 
	 */
	void Destroy();
private:
	static ChineseRemainderTransform *m_onlyInstance;
	static BigBinaryVector *m_rootOfUnityTable;
	static BigBinaryVector *m_rootOfUnityInverseTable;
	ChineseRemainderTransform(){}
	~ChineseRemainderTransform(){}
	ChineseRemainderTransform(const ChineseRemainderTransform&){}
	ChineseRemainderTransform& operator=(ChineseRemainderTransform const&){};
};

/**
 * @brief Golden Chinese Remainder Transform FFT implemetation.
 */
class ChineseRemainderTransformFTT : public LinearTransform
{
public:
	/**
	 * Get instance to return this object.
	 *
	 * @return is this object.	  	  
	 */
	static ChineseRemainderTransformFTT& GetInstance();

	/**
	 * Virtual forward transform.
	 *
	 * @param &element is the element to perform the transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	BigBinaryVector ForwardTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity, const usint CycloOrder) ;

	/**
	 * Virtual inverse transform.
	 *
	 * @param &element is the element to perform the inverse transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the inverse transform.	  	  
	 */
	BigBinaryVector InverseTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity, const usint CycloOrder) ;

	/**
	* Precomputation of root of unity tables.
	*
	* @param rootOfUnity the root of unity.
	* @param CycloOrder is the cyclotomic order.
	* @param modulus is the modulus
	*/
	void PreCompute(const BigBinaryInteger& rootOfUnity, const usint CycloOrder, const BigBinaryInteger &modulus);

	/**
	* Precomputation of root of unity tables.
	*
	* @param &rootOfUnity the root of unity.
	* @param CycloOrder is the cyclotomic order.
	* @param &moduliiChain is the modulus
	*/
	void PreCompute(std::vector<BigBinaryInteger> &rootOfUnity, const usint CycloOrder, std::vector<BigBinaryInteger> &moduliiChain);
	/**
	 * Destructor.	 
	 */
	void Destroy();
	
private:
	static ChineseRemainderTransformFTT *m_onlyInstance;
	static std::map<BigBinaryInteger,BigBinaryVector > m_rootOfUnityTableByModulus;
	static std::map<BigBinaryInteger,BigBinaryVector> m_rootOfUnityInverseTableByModulus;
	//static BigBinaryVector *m_rootOfUnityTable;
	
	//static BigBinaryVector *m_rootOfUnityInverseTable;
	//static BigBinaryVector *m_phiTable;
	//static BigBinaryVector *m_phiInverseTable;
	ChineseRemainderTransformFTT(){}
	~ChineseRemainderTransformFTT(){}
	ChineseRemainderTransformFTT(const ChineseRemainderTransform&){}
	ChineseRemainderTransformFTT& operator=(ChineseRemainderTransform const&){};
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
private:
};


} // namespace lbcrypto ends

#endif
