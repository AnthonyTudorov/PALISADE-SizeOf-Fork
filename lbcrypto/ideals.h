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
 * LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
 * This code provides basic lattice ideal manipulation functionality.
 */

#ifndef LBCRYPTO_IDEALS_H
#define LBCRYPTO_IDEALS_H

#include "binint.h"
#include "inttypes.h"
#include "nbtheory.h"
#include "ptxtencoding.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

// Interface for element params; all these methods have to be supported by any element parameters class
/**
 * @brief Interface for element params; all these methods have to be supported by any element parameters class
 */
class ElemParams  
{
public:
    //each element params should give the effective modulus regardless of the representation
	/**
	 * Each element params should give the effective modulus regardless of the representation
	 */
	virtual const BigBinaryInteger &GetModulus() const = 0;
};

// interface for ideal lattices
/**
 * @brief Interface for ideal lattices
 */
class ILElement
{
public:

	//Represent the lattice in binary format
	/**
	 * Convert the lattice to be represented internally in binary format.
	 *
	 * @param *text the byte array to take as input.  	
	 * @param &modulus modulus to convert from.  	  
	 */
	virtual void DecodeElement(ByteArrayPlaintextEncoding *text, const BigBinaryInteger &modulus) const = 0;
		
	//Convert binary string to lattice format
	/**
	 * Convert binary string to lattice format.
	 *
	 * @param &encoded the byte array to take as input.  	
	 * @param &modulus modulus to convert to.  	  
	 */
	virtual void EncodeElement(const ByteArrayPlaintextEncoding &encoded, const BigBinaryInteger &modulus) = 0;

};

// Parameters for ideal lattice: cyclotomic order and modulus
/**
 * @brief Parameters for ideal lattice: cyclotomic order and modulus.
 */
class ILParams : public ElemParams   
{
public:	

	/**
	 * Constructor that initializes nothing.
	 * All of the private members will be initialised to zero.
	 */
	ILParams() {
	}//no need of writing this as all of the private members will be initialised to zero
	
	// constructor for the pre-computed case;
	/**
	 * Constructor for the pre-computed case.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.
	 * @param &rootOfUnity the root of unity used in the ciphertext.	 
	 */
	ILParams (usint order, BigBinaryInteger &modulus, BigBinaryInteger& rootOfUnity) {
		m_modulus = modulus;	
		m_order = order;
		m_rootOfUnity = rootOfUnity;
	}

	/**
	 * Constructor for the pre-computed case.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.	 
	 */
	ILParams (usint order, BigBinaryInteger &modulus) {
		m_modulus = modulus;	
		m_order = order;
		m_rootOfUnity = RootOfUnity(order,modulus);
	}

	//copy constructor
	/**
	 * Copy constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.	 
	 */
	ILParams(const ILParams &rhs){
		m_modulus = rhs.m_modulus;
		m_order = rhs.m_order;
		m_rootOfUnity = rhs.m_rootOfUnity; 
	}

	/**
	 * Destructor.	 
	 */
	~ILParams() {
	}

	/**
	* Initialize the values - used with default constructor; the values are computed
	*
	* @param m the cyclotimic order.
	* @param bitLength minimum bit length for ciphertext modulus.
	*/
	bool Initialize(usint m, usint bitLength){
		//add a code that selects a modulus and computes a root of unity
	}

	/**
	* Initialize the values - used with default constructor; the values are imported from a pre-computed taxt file.
	*
	* @param m the cyclotimic order.
	* @param bitLength minimum bit length for ciphertext modulus.
	* @param &inputFile the full path to the text file containing the ciphertext modulues and root of unity for a given set of m and bitLength
	*/
	bool Initialize(usint m, usint bitLength, const std::string &inputfile){
		//add a code that sets all parameters using an entry in the text file with pre-computed values
	}

    // ACCESSORS

	// Get accessors
	/**
	 * Get method of the order.
	 *
	 * @return the order.	 
	 */
	usint GetOrder() const{
		return m_order;
	}

	/**
	 * Get the modulus.
	 *
	 * @return the modulus.	 
	 */
	const BigBinaryInteger &GetModulus() const {
		return m_modulus;
	}

	/**
	 * Get the root of unity.
	 *
	 * @return the root of unity.	 
	 */
	BigBinaryInteger &GetRootOfUnity() {
		return m_rootOfUnity;
	}

	// Set accessors
	/**
	 * Set method of the order.
	 *
	 * @param order the order variable.	  
	 */
	void SetOrder(usint order){
		m_order = order;
	}

	/**
	 * Set the root of unity.
	 *
	 * @param &rootOfUnity the root of unity.	  
	 */
	void SetRootOfUnity(const BigBinaryInteger &rootOfUnity){
		m_rootOfUnity = rootOfUnity;
	}

	/**
	 * Set the modulus.
	 *
	 * @param &modulus the modulus.	  
	 */
	void SetModulus(const BigBinaryInteger &modulus){
		m_modulus = modulus;
	}




private:
	// order of cyclotomic polynomial
	usint m_order;

	// value of modulus
	BigBinaryInteger m_modulus;

	// primitive root unity that is used to transform from coefficient to evaluation representation and vice versa
	BigBinaryInteger m_rootOfUnity;
};


} // namespace lbcrypto ends

#endif
