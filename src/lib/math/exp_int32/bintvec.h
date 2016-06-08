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
 * This file contains bintvec, a <vector> of bint, with associated math operators.
 * NOTE: this has been refactored so that implied modulo (ring)  aritmetic is in mbintvec
 *
 */

#ifndef LBCRYPTO_MATH_CPUINT_BINTVEC_H
#define LBCRYPTO_MATH_CPUINT_BINTVEC_H

#include <iostream>

//#include "binmat.h"
#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"

/**
 * @namespace exp_int32
 * The namespace of exp_int32
 */
namespace exp_int32 {
	

/**
 * @brief The class for representing vectors of bint.
 */
	//JSON FACILITY
	template <class bint_el_t>
	class bintvec : public lbcrypto::Serializable
{
public:
	/**
	 * Basic constructor.	  	  
	 */
	explicit bintvec();

	//	static inline bintvec Single(const bint_el_t& val) { //not sure this is needed
        //bintvec vec(1, modulus);
        //vec.SetValAtIndex(0, val);
        //return vec;
	//}

	/**
	 * Basic constructor for specifying the length of the vector.
	 *
	 * @param length is the length of the bintvec, in terms of the number of entries.	  	  
	 */
	explicit bintvec(usint length);

	/**
	 * Basic constructor for copying a vector
	 *
	 * @param bigBinaryVector is the bintvec to be copied.  	  
	 */
	explicit bintvec(const bintvec& other_bintvec);

	/**
	 * Basic move constructor for moving a vector
	 *
	 * @param &&bigBinaryVector is the bintvec to be moved.  	  
	 */
	bintvec(bintvec &&other_bintvec);//move copy constructor

	/**
	 * ???
	 *
	 * @param &rhs is the bintvec to test equality with.  
	 * @return the return value.	  
	 */
	bintvec&  operator=(const bintvec &rhs);

	/**
	 * ???
	 *
	 * @param &&rhs is the bintvec to test equality with.  
	 * @return the return value.	  
	 */
	bintvec&  operator=(bintvec &&rhs);

	inline bool operator==(const bintvec &b) const {
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

    inline bintvec& operator=(usint val) {
        *this->m_data[0] = val;
        for (size_t i = 1; i < GetLength(); ++i) {
            *this->m_data[i] = 0;
        }
        return *this;
    }

    inline bool operator!=(const bintvec &b) const {
        return !(*this == b);
    }

	/**
	 * Destructor.	  
	 */
	virtual ~bintvec();

	//ACCESSORS

	//change to ostream?
	/**
	 * ???
	 *
	 * @param os ???.
	 * @param &ptr_obj ???.
	 * @return the return value.	  
	 */
	template<class bint_el_t_c>
	friend std::ostream& operator<<(std::ostream& os, const bintvec<bint_el_t_c> &ptr_obj);

	/**
	 * Sets a value at an index.
	 *
	 * @param index is the index to set a value at.
	 * @param value is the value to set at the index.
	 */
	void SetValAtIndex(usint index, const bint_el_t& value);

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
	const bint_el_t& GetValAtIndex(usint index) const;

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
	bintvec Mod(const bint_el_t& modulus) const;
	
	//scalar operations

	/**
	 * Scalar addition.
	 *
	 * @param &b is the scalar to add at all locations.
	 * @return is the result of the addition operation.
	 */
	bintvec Add(const bint_el_t &b) const;

	/**
	 * Scalar subtraction.
	 *
	 * @param &b is the scalar to subtract from all locations.
	 * @return is the result of the subtraction operation.
	 */
	bintvec Sub(const bint_el_t &b) const;

	/**
	 * Scalar multiplication.
	 *
	 * @param &b is the scalar to multiply at all locations.
	 * @return is the result of the multiplication operation.
	 */
	bintvec Mul(const bint_el_t &b) const;

	/**
	 * Scalar exponentiation.
	 *
	 * @param &b is the scalar to exponentiate at all locations.
	 * @return is the result of the exponentiation operation.
	 */
	bintvec Exp(const bint_el_t &b) const;

	//vector operations

	//component-wise addition
	/**
	 * vector addition.
	 *
	 * @param &b is the vector to add at all locations.
	 * @return is the result of the addition operation.
	 */
	bintvec Add(const bintvec &b) const;

	/**
	 * vector +=
	 *
	 * @param &b is the vector to add to lhs
	 * @return is the result of the addition operation.
	 */
	const bintvec& operator+=(const bintvec &b);

	/**
	 * vector -=
	 *
	 * @param &b is the vector to subtract from lhs
	 * @return is the result of the addition operation.
	 * TODO: need to define what happens when b > a!!
	 */
	const bintvec& operator-=(const bintvec &b);

	//component-wise subtraction

	/**
	 * Vector subtraction.
	 *
	 * @param &b is the vector to subtract from lhs
	 * @return is the result of the subtraction operation.
	 * TODO: need to define what happens when b > a!
	 */
	bintvec Sub(const bintvec &b) const;

	//component-wise multiplication

	/**
	 * Vector multiplication.
	 *
	 * @param &b is the vector to multiply.
	 * @return is the result of the multiplication operation.
	 */
	bintvec Mul(const bintvec &b) const;

	/**
	 * Returns a vector of digit at a specific index for all entries for a given number base.
	 *
	 * @param index is the index to return the digit from in all entries.
	 * @param base is the base to use for the operation.
	 * @return is the resulting vector.
	 */
	bintvec GetDigitAtIndexForBase(usint index, usint base) const;

	//MANIPULATORS
	//useful for storing the results in the current instance of the class
	//they can also be added for scalar operations and modulo operation
   // bintvec&  operator+=(const bintvec& t) {*this = *this+t; return *this;}
	//bintvec&  operator*=(const bintvec& t) {return *this = *this*t;}
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
	bint_el_t **m_data;
	usint m_length;
	bool IndexCheck(usint) const;
};

//BINARY OPERATORS

/**
 *   scalar addition.
 *
 * @param &a is the input vector to add.
 * @param &i is the input integer to add.
 * @return is the result of the addition operation.
 */
template<class bint_el_t>
inline bintvec<bint_el_t> operator+(const bintvec<bint_el_t> &a, const bint_el_t &i) {return a.Add(i);}

/**
 *   scalar subtraction
 *
 * @param &a is the input vector to subtract.
 * @param &i is the input integer to subtract.
 * @return is the result of the subtraction operation.
 */
template<class bint_el_t>
inline bintvec<bint_el_t> operator-(const bintvec<bint_el_t> &a, const bint_el_t &i) {return a.Sub(i);}

/**
 *  scalar multiplication.
 *
 * @param &a is the input vector to multiply.
 * @param &i is the input integer to multiply.
 * @return is the result of the multiplication operation.
 */
template<class bint_el_t>
inline bintvec<bint_el_t> operator*(const bintvec<bint_el_t> &a, const bint_el_t &i) {return a.Mul(i);}

/**
 *  vector addition.
 *
 * @param &a is the first input vector to add.
 * @param &b is the second input vector to add.
 * @return is the result of the addition operation.
 */
template<class bint_el_t>
inline bintvec<bint_el_t> operator+(const bintvec<bint_el_t> &a, const bintvec<bint_el_t> &b) {return a.Add(b);}


/**
 *  vector subtraction.
 *
 * @param &a is the first input vector to subtract.
 * @param &b is the second input vector to subtract.
 * @return is the result of the subtraction operation.
 */
template<class bint_el_t>
inline bintvec<bint_el_t> operator-(const bintvec<bint_el_t> &a, const bintvec<bint_el_t> &b) {return a.Sub(b);}

/**
 *  vector multiplication.
 *
 * @param &a is the first input vector to multiply.
 * @param &b is the second input vector to multiply.
 * @return is the result of the multiplication operation.
 */
template<class bint_el_t>
inline bintvec<bint_el_t> operator*(const bintvec<bint_el_t> &a, const bintvec<bint_el_t> &b) {return a.Mul(b);}

} // namespace lbcrypto ends

#endif // LBCRYPTO_MATH_CPUINT_BINTVEC_H
