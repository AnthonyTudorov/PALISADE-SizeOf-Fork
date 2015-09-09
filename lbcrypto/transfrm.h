/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 *
 * All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.
 *
 * This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
 *
 * @section DESCRIPTION
 *
 * This file contains the linear transform interface functionality.
 */

#ifndef LBCRYPTO_TRANSFRM_H
#define LBCRYPTO_TRANSFRM_H

#include "binint.h"
#include "binvect.h"
#include "nbtheory.h"
#include "utilities.h"
#include <chrono>
#include <time.h>

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
	 * @param &element is the element to perform the transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
	 * @return is the output result of the transform.	  	  
	 */
	BigBinaryVector ForwardTransformIterative(const BigBinaryVector& element, const BigBinaryVector& rootOfUnityTable,const usint cycloOrder) ;

	/**
	 * Inverse transform.
	 *
	 * @param &element is the element to perform the transform on.
	 * @param rootOfUnity the root of unity.
	 * @param CycloOrder is the cyclotomic order.
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
	NumberTheoreticTransform(){}
	~NumberTheoreticTransform(){}
	NumberTheoreticTransform(const NumberTheoreticTransform&){}
	NumberTheoreticTransform& operator=(NumberTheoreticTransform const&){};
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
	 * Destructor.	 
	 */
	void Destroy();
private:
	static ChineseRemainderTransformFTT *m_onlyInstance;
	static BigBinaryVector *m_rootOfUnityTable;
	static BigBinaryVector *m_rootOfUnityInverseTable;
	static BigBinaryVector *m_phiTable;
	static BigBinaryVector *m_phiInverseTable;
	ChineseRemainderTransformFTT(){}
	~ChineseRemainderTransformFTT(){}
	ChineseRemainderTransformFTT(const ChineseRemainderTransform&){}
	ChineseRemainderTransformFTT& operator=(ChineseRemainderTransform const&){};
};

} // namespace lbcrypto ends

#endif
