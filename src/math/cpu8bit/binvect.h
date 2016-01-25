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

#ifndef LBCRYPTO_MATH_CPU8BIT_BINVECT_H
#define LBCRYPTO_MATH_CPU8BIT_BINVECT_H


#include "binint.h"
#include "binmat.h"
#include "../../utils/serializable.h"

/**
 * @namespace cpu8bit
 * The namespace of cpu8bit
 */
namespace cpu8bit {


//GENERAL NOTE. YSP. I believe we should use this class for vectors only. Matrices should be defined in a separate class: BigBinaryMatrix.

/**
 * @brief The class for representing vectors of big binary integers.
 */
	//JSON FACILITY
	class BigBinaryVector : public lbcrypto::BigBinaryVectorInterface, public lbcrypto::Serializable
{
public:
	/**
	 * Basic constructor.
	 */
	explicit BigBinaryVector();

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
	explicit BigBinaryVector(usint length, const BigBinaryInteger& modulus);

	/**
	 * Basic constructor for copying a vector
	 *
	 * @param bigBinaryVector is the big binary vector to be copied.
	 */
	explicit BigBinaryVector(const BigBinaryVector& bigBinaryVector);

	/**
	 * Basic constructor for copying a vector
	 *
	 * @param &&bigBinaryVector is the big binary vector to be copied.
	 */
	BigBinaryVector(BigBinaryVector &&bigBinaryVector);//move copy constructor

	/**
	 * ???
	 *
	 * @param &rhs is the big binary vector to test equality with.
	 * @return the return value.
	 */
	BigBinaryVector&  operator=(const BigBinaryVector &rhs);

	/**
	 * ???
     *
     * @param &&rhs is the big binary vector to test equality with.
     * @return the return value.
     */
    BigBinaryVector&  operator=(BigBinaryVector &&rhs);

    inline bool operator==(const BigBinaryVector &b) const {
        if (this->GetLength() != b.GetLength()) {
            return false;
        }
        for (size_t i = 0; i < this->GetLength(); ++i) {
            if (this->GetValAtIndex(i) != b.GetValAtIndex(i)) {
                return false;
            }
        }
        return true;
    }

    inline bool operator!=(const BigBinaryVector &b) const {
        return !(*this == b);
    }

	/**
	 * Destructor.
	 */
	~BigBinaryVector();

	//ACCESSORS

	//change to ostream?
	/**
	 * ???
	 *
	 * @param os ???.
	 * @param &ptr_obj ???.
	 * @return the return value.
	 */
	friend std::ostream& operator<<(std::ostream& os, const BigBinaryVector &ptr_obj);

	/**
	 * Sets a value at an index.
	 *
	 * @param index is the index to set a value at.
	 * @param value is the value to set at the index.
	 */
	void SetValAtIndex(usint index, const BigBinaryInteger& value);

	/**
	 * Sets a value at an index.
	 *
	 * @param index is the index to set a value at.
	 * @param str is the string representation of the value to set at the index.
	 */
	void SetValAtIndex(usint index, const std::string& str);

	/**
	 * Gets a value at an index.
	 *
	 * @param index is the index to set a value at.
	 * @return is the value at the index.
	 */
	const BigBinaryInteger& GetValAtIndex(usint index) const;

	/**
	 * indexing operation.
	 *
	 * @param index is the index to pull.
	 * @return is the result of the index operation.
	 */
	const BigBinaryInteger& operator[](usint index) const;

	/**
	 * Sets the vector modulus.
	 *
	 * @param value is the value to set.
	 */
	void SetModulus(const BigBinaryInteger& value);

	/**
	 * Gets the vector modulus.
	 *
	 * @return the vector modulus.
	 */
	const BigBinaryInteger& GetModulus() const;

	/**
	 * Gets the vector length.
	 *
	 * @return the vector length.
	 */
	usint GetLength() const;

	//METHODS

	/**
	 * returns the vector modulus with respect to the input value.
	 *
	 * @param modulus is the modulus to perform.
	 * @return is the result of the modulus operation.
	 */
	BigBinaryVector Mod(const BigBinaryInteger& modulus) const;

	//scalar operations

	/**
	 * Scalar modulus addition.
	 *
	 * @param &b is the scalar to add at all locations.
	 * @return is the result of the modulus addition operation.
	 */
	BigBinaryVector ModAdd(const BigBinaryInteger &b) const;

	/**
	 * Scalar modulus subtraction.
	 *
	 * @param &b is the scalar to subtract from all locations.
	 * @return is the result of the modulus subtraction operation.
	 */
	BigBinaryVector ModSub(const BigBinaryInteger &b) const;

	/**
	 * Scalar modulus multiplication.
	 *
	 * @param &b is the scalar to multiply at all locations.
	 * @return is the result of the modulus multiplication operation.
	 */
	BigBinaryVector ModMul(const BigBinaryInteger &b) const;

	/**
	 * Scalar modulus exponentiation.
	 *
	 * @param &b is the scalar to exponentiate at all locations.
	 * @return is the result of the modulus exponentiation operation.
	 */
	BigBinaryVector ModExp(const BigBinaryInteger &b) const;
	//BigBinaryVector& ScalarExp(const BigBinaryInteger &a) const;


	/**
	 * Modulus inverse.
	 *
	 * @return is the result of the modulus inverse operation.
	 */
	BigBinaryVector ModInverse() const;

	//vector operations

	//component-wise addition
	/**
	 * vector modulus addition.
	 *
	 * @param &b is the vector to add at all locations.
	 * @return is the result of the modulus addition operation.
	 */
	BigBinaryVector ModAdd(const BigBinaryVector &b) const;

	/**
	* Perform a modulus by 2 operation.  Returns the least significant bit.
	*
	* @return is the return value of the modulus by 2, also the least significant bit.
	*/
	BigBinaryVector ModByTwo() const;

	/**
	 * vector modulus addition.
	 *
	 * @param &b is the vector to add at all locations.
	 * @return is the result of the modulus addition operation.
	 */
	const BigBinaryVector& operator+=(const BigBinaryVector &b);

	//component-wise subtraction

	/**
	 * Vector modulus subtraction.
	 *
	 * @param &b is the vector to subtract.
	 * @return is the result of the modulus subtraction operation.
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

	//matrix operations

	//matrix product - used in FFT and IFFT; new_vector = A*this_vector

	/**
	 * Matrix by Vector modulus multiplication.  If this vector is x and the matrix is A, this method returns A*x.
	 *
	 * @param &a is the matrix to left-multiply with.
	 * @return is the result of the modulus multiplication operation.
	 */
	BigBinaryVector ModMatrixMul(const BigBinaryMatrix &a) const;

	/**
	 * Returns a vector of digit at a specific index for all entries for a given number base.
	 *
	 * @param index is the index to return the digit from in all entries.
	 * @param base is the base to use for the operation.
	 * @return is the resulting vector.
	 */
	BigBinaryVector GetDigitAtIndexForBase(usint index, usint base) const;

	//MANIPULATORS
	//useful for storing the results in the current instance of the class
	//they can also be added for scalar operations and modulo operation
   // BigBinaryVector&  operator+=(const BigBinaryVector& t) {*this = *this+t; return *this;}
	//BigBinaryVector&  operator*=(const BigBinaryVector& t) {return *this = *this*t;}
	//Gyana to add -= operator

	//JSON FACILITY
	/**
	* Implemented by this object only for inheritance requirements of abstract class Serializable.
	*
	* @param serializationMap stores this object's serialized attribute name value pairs.
	* @return map passed in.
	*/
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

	//JSON FACILITY
	/**
	* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
	*
	* @param serializationMap stores this object's serialized attribute name value pairs.
	* @return map updated with the attribute name value pairs required to serialize this object.
	*/
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

	//JSON FACILITY
	/**
	* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
	*
	* @param serializationMap stores this object's serialized attribute name value pairs.
	*/
	void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);

private:
	BigBinaryInteger **m_data;
	usint m_length;
	BigBinaryInteger m_modulus;
	bool IndexCheck(usint) const;
};

//BINARY OPERATORS

/**
 * Modulus scalar addition.
 *
 * @param &a is the input vector to add.
 * @param &i is the input integer to add.
 * @return is the result of the modulus addition operation.
 */
inline BigBinaryVector operator+(const BigBinaryVector &a, const BigBinaryInteger &i) {return a.ModAdd(i);}

/**
 * Modulus scalar multiplication.
 *
 * @param &a is the input vector to multiply.
 * @param &i is the input integer to multiply.
 * @return is the result of the modulus multiplication operation.
 */
inline BigBinaryVector operator*(const BigBinaryVector &a, const BigBinaryInteger &i) {return a.ModMul(i);}

/**
 * Modulus vector addition.
 *
 * @param &a is the first input vector to add.
 * @param &b is the second input vector to add.
 * @return is the result of the modulus addition operation.
 */
inline BigBinaryVector operator+(const BigBinaryVector &a, const BigBinaryVector &b) {return a.ModAdd(b);}

/**
 * Modulus vector multiplication.
 *
 * @param &a is the first input vector to multiply.
 * @param &b is the second input vector to multiply.
 * @return is the result of the modulus multiplication operation.
 */
inline BigBinaryVector operator*(const BigBinaryVector &a, const BigBinaryVector &b) {return a.ModMul(b);}
//Gyana to add both minus operators

} // namespace lbcrypto ends

#endif
