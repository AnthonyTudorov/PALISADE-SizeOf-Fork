/**
 * @file interface.h This file contains the interfaces for math data types
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
 

#ifndef LBCRYPTO_MATH_INTERFACE_H
#define LBCRYPTO_MATH_INTERFACE_H

#include "utils/inttypes.h"

namespace lbcrypto {

	template<typename T>
	class BigIntegerInterface
	{
	public:

#if 0
		/**
		 * ???
		 *
		 * @param &rhs is the big binary integer to test equality with.  
		 * @return the return value.	  
		 */
		virtual T& operator=(const T &rhs) = 0;

		/**
		 * ???
		 *
		 * @param &&rhs is the big binary integer to test equality with.  
		 * @return the return value.	  
		 */
		virtual T&  operator=(T &&rhs) = 0;
#endif

		//ACCESSORS

#if 0
		/**
		 * Basic set method for setting the value of a big binary integer
		 *
		 * @param str is the string representation of the big binary integer to be copied.  	  
		 */
		virtual void SetValue(const std::string& str) = 0;
#endif

		virtual ~BigIntegerInterface() {}

		//// ADDITION

		/**
		 * + operation.
		 *
		 * @param b is the value to add.
		 * @return result of the addition
		 */
		virtual T Plus(const T& b) const = 0;

		/**
		 * += operation.
		 *
		 * @param b is the value to add.
		 * @return reference the result of the addition
		 */
		virtual const T& PlusEq(const T& b) = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		virtual T ModAdd(const T& b, const T& modulus) const = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		virtual const T& ModAddEq(const T& b, const T& modulus) = 0;

		T operator+(const T& b) const { return this->Plus(b); }
		const T& operator+=(const T& b) { return this->PlusEq(b); }

		//// MULTIPLICATION

		/**
		 * Multiplication operation.
		 *
		 * @param b is the value to multiply with.
		 * @return is the result of the multiplication operation.
		 */
		virtual T Times(const T& b) const = 0;

		/**
		 * Multiplication operation.
		 *
		 * @param b is the value to multiply with.
		 * @return is the result of the multiplication operation.
		 */
		virtual const T& TimesEq(const T& b) = 0;

		T operator*(const T& b) const { return this->Times(b); }
		const T& operator*=(const T& b) { return this->TimesEq(b); }

#if 0
		/**
		 * Subtraction operation.
		 *
		 * @param b is the value to subtract.
		 * @return is the result of the subtraction operation.
		 */
		virtual T Minus(const T& b) const = 0;


		///**
		// * Division operation.
		// *
		// * @param b is the value to divide by.
		// * @return is the result of the division operation.
		// */
		virtual T DividedBy(const T& b) const = 0;

		//modular arithmetic operations

		/**
		 * returns the modulus with respect to the input value.
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus operation.
		 */
		virtual T Mod(const T& modulus) const = 0;

		/**
		 * returns the Barret modulus with respect to the input modulus and the Barrett value.
		 *
		 * @param modulus is the modulus to perform.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus operation.
		 */
		virtual T ModBarrett(const T& modulus, const T& mu) const = 0;

		/**
		 * returns the modulus inverse with respect to the input value.
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus inverse operation.
		 */
		virtual T ModInverse(const T& modulus) const = 0;

		/**
		 * Scalar modulus subtraction.
		 *
		 * @param &b is the scalar to subtract.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus subtraction operation.
		 */
		virtual T ModSub(const T& b, const T& modulus) const = 0;

		/**
		 * Scalar modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModMul(const T& b, const T& modulus) const = 0;

		/**
		 * Scalar Barrett modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModBarrettMul(const T& b, const T& modulus,const T& mu) const = 0;

		/**
		 * Scalar modulus exponentiation.
		 *
		 * @param &b is the scalar to exponentiate at all locations.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus exponentiation operation.
		 */
		virtual T ModExp(const T& b, const T& modulus) const = 0;

		/**
		 * Subtraction accumulator.
		 *
		 * @param &b is the value to subtract.
		 * @return is the result of the subtraction operation.
		 */
		virtual const T& operator-=(const T &b) = 0;

		////bit shifting operators

		/**
		 * Left shift operator and creates a new variable as output.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual T  operator<<(usshort shift) const = 0;

		/**
		 * Right shift operator and creates a new variable as output.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual T  operator>>(usshort shift) const = 0;

		/**
		 * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual const T& operator<<=(usshort shift) = 0;

		/**
		 * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual const T& operator>>=(usshort shift) = 0;

		//virtual friend methods are not allowed in abstract classes
		//input/output operators
		/**
		 * ???
		 *
		 * @param os the output stream.
		 * @param &ptr_obj ???.
		 * @return the return value.	  
		 */
		//virtual friend std::ostream& operator<<(std::ostream& os, const T &ptr_obj);

		/**
		 * Stores the value of this T in a string object and returns it.
		 * Added by Arnab Deb Gupta <ad479@njit.edu> on 9/21/15.
		 *
		 * @return the value of this T as a string.
		 */
		virtual std::string ToString() const = 0;

		/**
		 * Returns the MSB location of the value.
		 *
		 * @return the index of the most significant bit.	  
		 */
		virtual usint GetMSB()const = 0;

		/**
		 * Get the number of digits using a specific base - support for arbitrary base may be needed.
		 *
		 * @param base is the base with which to determine length in.
		 * @return the length of the representation in a specific base.	  
		 */
		virtual usint GetLengthForBase(usint base) const = 0;

		/**
		 * Get the number of digits using a specific base - support for arbitrary base may be needed.
		 *
		 * @param index is the location to return value from in the specific base.
		 * @param base is the base with which to determine length in.
		 * @return the length of the representation in a specific base.	  
		 */
		virtual usint GetDigitAtIndexForBase(usint index, usint base) const = 0;

		/**
		 * Convert the value to an int.
		 *
		 * @return the int representation of the value.	  
		 */
		virtual usint ConvertToInt() const = 0;

		//static methods cannot be added to the interface
		/**
		 * Convert a value from an int to a T.
		 *
		 * @param the value to convert from.
		 * @return the int represented as a big binary int.	  
		 */
		//static T intToBigIntegereger(usint m);

		////constant definations

		/**
		 * Constant zero.	  
		 */
		//const static T ZERO;

		/**
		 * Constant one.	  
		 */
		//const static T ONE;

		/**
		 * Constant two.	  
		 */
		//const static T TWO;

		/**
		 * Test equality of the inputs.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the inputs are equal.	  
		 */
		//friend bool operator==(const T& a, const T& b);

		/**
		 * Test inequality of the inputs.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the inputs are inequal.	  
		 */
		//friend bool operator!=(const T& a, const T& b);

		/**
		 * Test if first input is great than the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is greater.
		 */
		//friend bool operator> (const T& a, const T& b);

		/**
		 * Test if first input is great than or equal to the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is greater than or equal to the second input.
		 */
		//friend bool operator>=(const T& a, const T& b);

		/**
		 * Test if first input is less than the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is lesser.
		 */
		//friend bool operator< (const T& a, const T& b);

		/**
		 * Test if first input is less than or equal to the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is less than or equal to the second input.
		 */
		//friend bool operator<=(const T& a, const T& b);
#endif
	}; 

#if 0
	//overloaded binary operators based on integer arithmetic and comparison functions
	/**
		* Addition operation.
		*
		* @param a is the value to add.
		* @param b is the value to add.
		* @return is the result of the addition operation.
	*/
	//inline BigIntegeregerInterface operator+(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.Plus(b);}

	/**
		* Subtraction operation.
		*
		* @param a is the value to subtract from.
		* @param b is the value to subtract.
		* @return is the result of the subtraction operation.
	*/
	//inline BigIntegeregerInterface operator-(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.Minus(b);}

	/**
		* Multiplication operation.
		*
		* @param a is the value to multiply with.
		* @param b is the value to multiply with.
		* @return is the result of the multiplication operation.
	*/
	//inline BigIntegeregerInterface operator*(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.Times(b);}

	/**
		* Division operation.
		*
		* @param a is the value to divide.
		* @param b is the value to divide by.
		* @return is the result of the division operation.
	*/
	//inline BigIntegeregerInterface operator/(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.DividedBy(b);}
#endif

	template<typename T, typename I>
	class BigVectorInterface{
public:
		virtual ~BigVectorInterface() {}

#if 0
		/**
		* Assignment operator to assign value from rhs
		*
		* @param &rhs is the native vector to be assigned from.
		* @return Assigned T.
		*/
		const T& operator=(const T &rhs);

		/**
		* Move assignment operator
		*
		* @param &&rhs is the native vector to be moved.
		* @return moved T object
		*/
		T&  operator=(T &&rhs);

		//todo replace <sint> with <usint>
		/**
		* Initializer list for T.
		*
		* @param &&rhs is the list of integers to be assigned to the BBV.
		* @return T object
		*/
		const T& operator=(std::initializer_list<sint> rhs);

		/**
		* Initializer list for T.
		*
		* @param &&rhs is the list of strings containing integers to be assigned to the BBV.
		* @return T object
		*/
		const T& operator=(std::initializer_list<std::string> rhs);
#endif

#if 0
		/**
		* Equals to operator, checks if two T obj are equal or not.
		*
		* @param b is vector to be compared.
		* @return true if equal and false otherwise.
		*/
		inline bool operator==(const T &b) const {
	        if (this->GetLength() != b.GetLength())
	            return false;
	        if (this->GetModulus() != b.GetModulus())
	        	return false;
	        for (size_t i = 0; i < this->GetLength(); ++i) {
	            if (this->at(i) != b.at(i)) {
	                return false;
	            }
	        }
	        return true;
	    }

	    /**
		* Assignment operator to assign value val to first entry, 0 for the rest of entries.
		*
		* @param val is the value to be assigned at the first entry.
		* @return Assigned T.
		*/
	    inline const T& operator=(usint val) {
	        this->m_data[0] = val;
	        for (size_t i = 1; i < GetLength(); ++i) {
	            this->m_data[i] = 0;
	        }
	        return *this;
	    }

	    /**
		* Inequality operator, checks if two T obj are equal or not.
		*
		* @param b is vector to be compared.
		* @return false  if not equal and false otherwise.
		*/
	    inline bool operator!=(const T &b) const {
	        return !(*this == b);
	    }
#endif
		//ACCESSORS

#if 0
		/**
		* ostream operator to output vector values to console
		*
		* @param os is the std ostream object.
		* @param &ptr_obj is the T object to be printed.
		* @return std ostream object which captures the vector values.
		*/
		template<class IntegerType_c>
		friend std::ostream& operator<<(std::ostream& os, const T<IntegerType_c> &ptr_obj);

		T::BVInt& at(usint i) {
		  if(!this->IndexCheck(i)) {
		    throw std::logic_error("index out of range in NativeVector");
		  }
		  return this->m_data[i];
		  }

		const T::BVInt& at(usint i) const {
	 	  if(!this->IndexCheck(i)) {
		    throw std::logic_error("index out of range in NativeVector");
		  }
		  return this->m_data[i];
		}

		void atMod(usint i, const T::BVInt &val) {
		  if(!this->IndexCheck(i)) {
		    throw std::logic_error("index out of range in NativeVector");
		  }
		  this->m_data[i]=val%m_modulus;
		  return;
		}

		void atMod(usint i, const std::string& val) const {
	 	  if(!this->IndexCheck(i)) {
		    throw std::logic_error("index out of range in NativeVector");
		  }
		  T::BVInt tmp(val);
		  this->m_data[i]=tmp%m_modulus;
		  return;
		}

		/**
		 * operators to get a value at an index.
		 * @param idx is the index to get a value at.
		 * @return is the value at the index. return NULL if invalid index.
		 */
		inline T::BVInt& operator[](std::size_t idx) { return (this->m_data[idx]); }
		inline const T::BVInt& operator[](std::size_t idx) const { return (this->m_data[idx]); }
#endif

#if 0
		/**
		 * Sets the vector modulus.
		 *
		 * @param value is the value to set.
		 * @param value is the modulus value to set.
		 */
		void SetModulus(const T::BVInt& value);

		/**
		 * Sets the vector modulus and changes the values to match the new modulus.
		 *
		 * @param value is the value to set.
		 */
		void SwitchModulus(const T::BVInt& value);

		/**
		 * Gets the vector modulus.
		 *
		 * @return the vector modulus.
		 */
		const T::BVInt& GetModulus() const;

		/**
		 * Gets the vector length.
		 *
		 * @return vector length.
		 */
		usint GetLength() const;
#endif

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual T ModAdd(const I &b) const = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual const T& ModAddEq(const I &b) = 0;

		/**
		 * Scalar modulus addition at a particular index.
		 *
		 * @param &b is the scalar to add.
		 * @param i is the index of the entry to add.
		 * @return is the result of the modulus addition operation.
		 */
		virtual T ModAddAtIndex(usint i, const I &b) const = 0;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual T ModAdd(const T &b) const = 0;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual const T& ModAddEq(const T &b) = 0;

		T operator+(const I &b) const { return this->ModAdd(b); }
		const T& operator+=(const I &b) { return this->ModAddEq(b); }
		T operator+(const T &b) const { return this->ModAdd(b); }
		const T& operator+=(const T &b) { return this->ModAddEq(b); }

		/**
		 * Scalar modular multiplication.
		 *
		 * @param &b is the scalar to multiply at all locations.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModMul(const I &b) const = 0;

		/**
		 * Scalar modular multiplication.
		 *
		 * @param &b is the scalar to multiply at all locations.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual const T& ModMulEq(const I &b) = 0;

		/**
		 * Vector modulus multiplication.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModMul(const T &b) const = 0;

		/**
		 * Vector modulus multiplication.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual const T& ModMulEq(const T &b) = 0;

		T operator*(const I &b) const { return this->ModMul(b); }
		const T& operator*=(const I &b) { return this->ModMulEq(b); }
		T operator*(const T &b) const { return this->ModMul(b); }
		const T& operator*=(const T &b) { return this->ModMulEq(b); }

#if 0
		/**
		 * Vector Modulus operator.
		 *
		 * @param modulus is the modulus to perform on the current vector entries.
		 * @return a new vector after the modulus operation on current vector.
		 */
		T Mod(const T::BVInt& modulus) const;

		//scalar operations


		/**
		 * Scalar modulus subtraction.
		 * After substraction modulus operation is performed with the current vector modulus.
		 * @param &b is the scalar to subtract from all locations.
		 * @return a new vector which is the result of the modulus substraction operation.
		 */
		T ModSub(const T::BVInt &b) const;

		/**
		 * Scalar modulus exponentiation.
		 *
		 * @param &b is the scalar to exponentiate at all locations.
		 * @return a new vector which is the result of the modulus exponentiation operation.
		 */
		T ModExp(const T::BVInt &b) const;
		//T& ScalarExp(const BigInteger &a) const;


		/**
		 * Modulus inverse.
		 *
		 * @return a new vector which is the result of the modulus inverse operation.
		 */
		T ModInverse() const;

		/**
		 * Modulus scalar multiplication assignment.
		 *
		 * @param &a is the input vector to multiply.
		 * @param &i is the input integer to multiply at all entries.
		 * @return a new vector which is the result of the modulus multiplication operation.
		 */
		T &operator*=(const T::BVInt &i) {
		    *this=this->ModMul(i);
		    return *this;
		  }

		//Vector Operations

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return a new vector which is the return value of the modulus by 2, also the least significant bit.
		*/
		T ModByTwo() const;

#endif

#if 0
		/**
	 	 * Vector Self Modulus Substraction.
	 	 *
		 * @param &b is the vector to substract.
		 * @return a reference to the result of the modulus substraction operation.
		 */
		const T& operator-=(const T &b);

		//component-wise subtraction

		/**
		 * Vector Modulus subtraction.
		 *
		 * @param &b is the vector to subtract.
		 * @return a new vector which is the result of the modulus subtraction operation.
		 */
		T ModSub(const T &b) const;

		//component-wise multiplication

		/**
		 * Vector multiplication without applying the modulus operation.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the multiplication operation.
		 */
		T MultWithOutMod(const T &b) const;

		/**
		* Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where [] is the rounding operation.
		*
		* @param p is the numerator to be multiplied.
		* @param q is the denominator to be divided.
		* @return the result of multiply and round.
		*/
		T MultiplyAndRound(const T::BVInt &p, const T::BVInt &q) const;

		/**
		* Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is the rounding operation.
		*
		* @param q is the denominator to be divided.
		* @return the result of divide and round.
		*/
		T DivideAndRound(const T::BVInt &q) const;

		//matrix operations

		//matrix product - used in FFT and IFFT; new_vector = A*this_vector

		/**
		 * Returns a vector of digits at a specific index for all entries for a given number base.
		 *
		 * @param index is the index to return the digit from in all entries.
		 * @param base is the base to use for the operation.
		 * @return is the resulting vector.
		 */
		T GetDigitAtIndexForBase(usint index, usint base) const;
#endif
	};

	// TODO
	class BigMatrixInterface{};

} // namespace lbcrypto ends

#endif
