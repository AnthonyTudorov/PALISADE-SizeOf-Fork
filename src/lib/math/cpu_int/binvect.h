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
 * This file contains the vector manipulation functionality.
 */

#ifndef LBCRYPTO_MATH_CPUINT_BINVECT_H
#define LBCRYPTO_MATH_CPUINT_BINVECT_H

#include <iostream>

#include "../../utils/serializable.h"
#include "../../utils/inttypes.h"
 #include <initializer_list>

/**
 * @namespace cpu8bit
 * The namespace of cpu8bit
 */
namespace cpu_int {
	


/**
 * @brief The class for representing vectors of big binary integers.
 */
	//JSON FACILITY INHERITANCE
	template <class IntegerType>
	class BigBinaryVector : public lbcrypto::Serializable
{
public:
	/**
	 * Basic constructor.	  	  
	 */
	explicit BigBinaryVector();

    static inline BigBinaryVector Single(const IntegerType& val, const IntegerType& modulus) {
        BigBinaryVector vec(1, modulus);
        vec.SetValAtIndex(0, val);
        return vec;
    }

	/**
	 * Basic constructor for specifying the length of the vector.
	 *
	 * @param length is the length of the big binary vector, in terms of the number of entries.	  	  
	 */
	explicit BigBinaryVector(usint length);

	/**
	 * Basic constructor for specifying the length of the vector and the modulus.
	 *
	 * @param length is the length of the big binary vector, in terms of the number of entries.	
	 * @param modulus is the modulus of the entries in the vector.  	  
	 */
	explicit BigBinaryVector(usint length, const IntegerType& modulus);

	/**
	 * Basic constructor for copying a vector
	 *
	 * @param bigBinaryVector is the big binary vector to be copied.  	  
	 */
	explicit BigBinaryVector(const BigBinaryVector& bigBinaryVector);

	/**
	 * Basic move constructor for moving a vector
	 *
	 * @param &&bigBinaryVector is the big binary vector to be moved.  	  
	 */
	BigBinaryVector(BigBinaryVector &&bigBinaryVector);//move copy constructor

	/**
	* Assignment operator to assign value from rhs
	*
	* @param &rhs is the big binary vector to be assigned from.
	* @return Assigned BigBinaryVector.	  
	*/
	const BigBinaryVector& operator=(const BigBinaryVector &rhs);

	/**
	* Move assignment operator
	*
	* @param &&rhs is the big binary vector to be moved.
	* @return moved BigBinaryVector object  
	*/
	BigBinaryVector&  operator=(BigBinaryVector &&rhs);

	/**
	* Initializer list for BigBinaryVector.
	*
	* @param &&rhs is the list of integers to be assigned to the BBV.
	* @return BigBinaryVector object 
	*/
	const BigBinaryVector& operator=(std::initializer_list<sint> rhs);

	/**
	* Equals to operator, checks if two BigBinaryVector obj are equal or not.
	*
	* @param b is vector to be compared.
	* @return true if equal and false otherwise.
	*/
	inline bool operator==(const BigBinaryVector &b) const {
        if (this->GetLength() != b.GetLength())
            return false;
        if (this->GetModulus() != b.GetModulus())
        	return false;
        for (size_t i = 0; i < this->GetLength(); ++i) {
            if (this->GetValAtIndex(i) != b.GetValAtIndex(i)) {
                return false;
            }
        }
        return true;
    }

    /**
	* Assignment operator to assign value val to first entry, 0 for the rest of entries.
	*
	* @param val is the value to be assigned at the first entry.
	* @return Assigned BigBinaryVector.
	*/
    inline const BigBinaryVector& operator=(usint val) {
        this->m_data[0] = val;
        for (size_t i = 1; i < GetLength(); ++i) {
            this->m_data[i] = 0;
        }
        return *this;
    }

    /**
	* Inequality operator, checks if two BigBinaryVector obj are equal or not.
	*
	* @param b is vector to be compared.
	* @return false  if not equal and false otherwise.
	*/
    inline bool operator!=(const BigBinaryVector &b) const {
        return !(*this == b);
    }

	/**
	* Destructor.	  
	*/
	virtual ~BigBinaryVector();

	//ACCESSORS

	/**
	* ostream operator to output vector values to console
	*
	* @param os is the std ostream object.
	* @param &ptr_obj is the BigBinaryVector object to be printed.
	* @return std ostream object which captures the vector values.
	*/
	template<class IntegerType_c>
	friend std::ostream& operator<<(std::ostream& os, const BigBinaryVector<IntegerType_c> &ptr_obj);

	/**
	 * Sets a value at an index.
	 *
	 * @param index is the index to set a value at.
	 * @param value is the int value to set at the index.
	 */
	void SetValAtIndex(usint index, const IntegerType& value);

	/**
	 * Sets a value at an index.
	 *
	 * @param index is the index to set a value at.
	 * @param str is the string representation of the value to set at the index.
	 */
	void SetValAtIndex(usint index, const std::string& str);

	/**
	 * Gets a value stored at an index.
	 *
	 * @param index is the index from the vector entries.
	 * @return value at the index.
	 */
	const IntegerType& GetValAtIndex(usint index) const;

	/**
	 * Sets the vector modulus.
	 *
	 * @param value is the value to set.
	 * @param value is the modulus value to set.
	 */
	void SetModulus(const IntegerType& value);

	/**
	 * Sets the vector modulus and changes the values to match the new modulus.
	 *
	 * @param value is the value to set.
	 */
	void SwitchModulus(const IntegerType& value);

	/**
	 * Gets the vector modulus.
	 *
	 * @return the vector modulus.
	 */
	const IntegerType& GetModulus() const;

	/**
	 * Gets the vector length.
	 *
	 * @return vector length.
	 */
	usint GetLength() const;
	
	//METHODS

	/**
	 * Vector Modulus operator.
	 *
	 * @param modulus is the modulus to perform on the current vector entries.
	 * @return a new vector after the modulus operation on current vector.
	 */
	BigBinaryVector Mod(const IntegerType& modulus) const;
	
	//scalar operations

	/**
	 * Scalar modulus addition at a particular index.
	 *
	 * @param &b is the scalar to add.
	 * @param i is the index of the entry to add.
	 * @return is the result of the modulus addition operation.
	 */
	BigBinaryVector ModAddAtIndex(usint i, const IntegerType &b) const;

	/**
	 * Scalar modulus addition.
	 *
	 * After addition modulus operation is performed with the current vector modulus.
	 * @return a new vector which is the result of the modulus addition operation.
	 */
	BigBinaryVector ModAdd(const IntegerType &b) const;	

	/**
	 * Scalar modulus subtraction.
	 * After substraction modulus operation is performed with the current vector modulus.
	 * @param &b is the scalar to subtract from all locations.
	 * @return a new vector which is the result of the modulus substraction operation.
	 */
	BigBinaryVector ModSub(const IntegerType &b) const;

	/**
	 * Scalar modular multiplication. Generalized Barrett modulo reduction algorithm. 
	 * See the comments in the cpp files for details of the implementation.
	 *
	 * @param &b is the scalar to multiply at all locations.
	 * @return is the result of the modulus multiplication operation.
	 */
	BigBinaryVector ModMul(const IntegerType &b) const;

	/**
	 * Scalar modulus exponentiation.
	 *
	 * @param &b is the scalar to exponentiate at all locations.
	 * @return a new vector which is the result of the modulus exponentiation operation.
	 */
	BigBinaryVector ModExp(const IntegerType &b) const;
	//BigBinaryVector& ScalarExp(const BigBinaryInteger &a) const;
	

	/**
	 * Modulus inverse.
	 *
	 * @return a new vector which is the result of the modulus inverse operation.
	 */
	BigBinaryVector ModInverse() const;

	//Vector Operations

	//component-wise addition
	/**
	 * vector modulus addition.
	 *
	 * @param &b is the vector to add at all locations.
	 * @return a new vector which is the result of the modulus addition operation.
	 */
	BigBinaryVector ModAdd(const BigBinaryVector &b) const;

	/**
	* Perform a modulus by 2 operation.  Returns the least significant bit.
	*
	* @return a new vector which is the return value of the modulus by 2, also the least significant bit.
	*/
	BigBinaryVector ModByTwo() const;

	/**
	 * Vector Self Modulus Addition.
	 *
	 * @param &b is the vector to add.
	 * @return a reference to the result of the modulus addition operation.
	 */
	const BigBinaryVector& operator+=(const BigBinaryVector &b);


	/**
 	 * Vector Self Modulus Substraction.
 	 *
	 * @param &b is the vector to substract.
	 * @return a reference to the result of the modulus substraction operation.
	 */
	const BigBinaryVector& operator-=(const BigBinaryVector &b);

	//component-wise subtraction

	/**
	 * Vector Modulus subtraction.
	 *
	 * @param &b is the vector to subtract.
	 * @return a new vector which is the result of the modulus subtraction operation.
	 */
	BigBinaryVector ModSub(const BigBinaryVector &b) const;

	//component-wise multiplication

	/**
	 * Vector modulus multiplication.
	 *
	 * @param &b is the vector to multiply.
	 * @return is the result of the modulus multiplication operation.
	 */
	BigBinaryVector ModMul(const BigBinaryVector &b) const;

	/**
	 * Vector multiplication.
	 *
	 * @param &b is the vector to multiply.
	 * @return is the result of the multiplication operation.
	 */
	BigBinaryVector MultWithOutMod(const BigBinaryVector &b) const;

	/**
	* Multiply and Rounding operation on a bigBinaryInteger x. Returns [x*p/q] where [] is the rounding operation.
	*
	* @param p is the numerator to be multiplied.
	* @param q is the denominator to be divided.
	* @return the result of multiply and round.
	*/
	BigBinaryVector MultiplyAndRound(const IntegerType &p, const IntegerType &q) const;

	/**
	* Multiply and Rounding operation for a product of two polynomials. Returns [this*v*p/q] where [] is the rounding operation.
	*
	* @param v is the polynomial multiplicand.
	* @param p is the integer multiplicand.
	* @param q is the integer divisor.
	* @return the result of multiply and round.
	*/
	BigBinaryVector MultiplyAndRound(const BigBinaryVector &v, const IntegerType &p, const IntegerType &q) const;

	/**
	* Multiply and Rounding operation for a sum of two polynomial products. Returns [(this*v1+v2*v3)*p/q] where [] is the rounding operation.
	*
	* @param v1 is the first polynomial.
	* @param v2 is the second polynomial
	* @param v3 is the third polynomial.
	* @param p is the integer multiplicand.
	* @param q is the integer divisor.
	* @return the result of multiply and round.
	*/
	BigBinaryVector MultiplyAndRound(const BigBinaryVector &v1, const BigBinaryVector &v2, const BigBinaryVector &v3, const IntegerType &p, const IntegerType &q) const;


	/**
	* Divide and Rounding operation on a bigBinaryInteger x. Returns [x/q] where [] is the rounding operation.
	*
	* @param q is the denominator to be divided.
	* @return the result of divide and round.
	*/
	BigBinaryVector DivideAndRound(const IntegerType &q) const;

	//matrix operations
	
	//matrix product - used in FFT and IFFT; new_vector = A*this_vector

	/**
	 * Matrix by Vector modulus multiplication.  If this vector is x and the matrix is A, this method returns A*x.
	 *
	 * @param &a is the matrix to left-multiply with.
	 * @return is the result of the modulus multiplication operation.
	 */
	//BigBinaryVector ModMatrixMul(const BigBinaryMatrix &a) const;

	/**
	 * Returns a vector of digit at a specific index for all entries for a given number base.
	 *
	 * @param index is the index to return the digit from in all entries.
	 * @param base is the base to use for the operation.
	 * @return is the resulting vector.
	 */
	BigBinaryVector GetDigitAtIndexForBase(usint index, usint base) const;


	//JSON FACILITY
	/**
	* Serialize the object into a Serialized
	* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	* @param fileFlag is an object-specific parameter for the serialization
	* @return true if successfully serialized
	*/
	bool Serialize(lbcrypto::Serialized* serObj, const std::string fileFlag = "") const;

	/**
	* Populate the object from the deserialization of the Setialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool Deserialize(const lbcrypto::Serialized& serObj);

private:
	//m_data is a pointer to the vector
	IntegerType *m_data;
	//m_length stores the length of the vector
	usint m_length;
	//m_modulus stores the internal modulus of the vector.
	IntegerType m_modulus;
	//function to check if the index is a valid index.
	bool IndexCheck(usint) const;
};

//BINARY OPERATORS

/**
 * Modulus scalar addition.
 *
 * @param &a is the input vector to add.
 * @param &i is the input integer to add at all entries.
 * @return a new vector which is the result of the modulus addition operation.
 */
template<class IntegerType>
inline BigBinaryVector<IntegerType> operator+(const BigBinaryVector<IntegerType> &a, const IntegerType &i) {return a.ModAdd(i);}

/**
* Modulus scalar substraction.
*
* @param &a is the input vector to substract from.
* @param &i is the input integer to substract at all entries.
* @return a new vector which is the result of the modulus substraction operation.
*/
template<class IntegerType>
inline BigBinaryVector<IntegerType> operator-(const BigBinaryVector<IntegerType> &a, const IntegerType &i) {return a.ModSub(i);}

/**
 * Modulus scalar multiplication.
 *
 * @param &a is the input vector to multiply.
 * @param &i is the input integer to multiply at all entries.
 * @return a new vector which is the result of the modulus multiplication operation.
 */
template<class IntegerType>
inline BigBinaryVector<IntegerType> operator*(const BigBinaryVector<IntegerType> &a, const IntegerType &i) {return a.ModMul(i);}

/**
 * Modulus vector addition.
 *
 * @param &a is the first input vector to add.
 * @param &b is the second input vector to add.
 * @return is the result of the modulus addition operation.
 */
template<class IntegerType>
inline BigBinaryVector<IntegerType> operator+(const BigBinaryVector<IntegerType> &a, const BigBinaryVector<IntegerType> &b) {return a.ModAdd(b);}


/**
 * Modulus vector substraction.
 *
 * @param &a is the first input vector.
 * @param &b is the second input vector.
 * @return is the result of the modulus substraction operation.
 */
 template<class IntegerType>
 inline BigBinaryVector<IntegerType> operator-(const BigBinaryVector<IntegerType> &a, const BigBinaryVector<IntegerType> &b) {return a.ModSub(b);}
 
 /**
  * Modulus vector multiplication.
  *
  * @param &a is the first input vector to multiply.
  */
 template<class IntegerType>
 inline BigBinaryVector<IntegerType> operator*(const BigBinaryVector<IntegerType> &a, const BigBinaryVector<IntegerType> &b) {return a.ModMul(b);}


} // namespace lbcrypto ends

#endif
