/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>
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

#ifndef LBCRYPTO_LATTICE_ILDCRTELEMENT_H
#define LBCRYPTO_LATTICE_ILDCRTELEMENT_H

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"
//#include "../encoding/ptxtencoding.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	// Parameters for an array of ideal lattices (used for Double-CRT)
	/**
	* @brief Parameters for array of ideal lattices (used for Double-CRT)
	*/
	class ILDCRTParams : public ElemParams {
	public:

		
		/**
		* Constructor that initializes nothing.
		*/
		ILDCRTParams() {}

		/**
		* Constructor with all parameters provided.
		*
		* @param rootsOfUnity the roots of unity for the chain of moduli
		* @param cyclotomic_order the order of the ciphertext
		* @param &moduli is the tower of moduli
		* @param &modulus is the multiplication of all moduli. This value is used for interpolation.
		*/
		ILDCRTParams(std::vector<BigBinaryInteger>& rootsOfUnity, usint cyclotomic_order, std::vector<BigBinaryInteger> &moduli, BigBinaryInteger &modulus) {
			m_cyclotomicOrder = cyclotomic_order;
			m_moduli = moduli;
			m_rootsOfUnity = rootsOfUnity;
			m_modulus = modulus;
			m_rootOfUnity = RootOfUnity(cyclotomic_order, modulus);
		}

		/**
		* Constructor with all parameters provided except the multiplied values of the chain of moduli. That value is automatically calculated. Root of unity of the modulus is also calculated. 
		*
		* @param rootsOfUnity the roots of unity for the chain of moduli
		* @param cyclotomic_order the order of the ciphertext
		* @param &moduli is the tower of moduli
		*/
		ILDCRTParams(std::vector<BigBinaryInteger>& rootsOfUnity, usint cyclotomic_order, std::vector<BigBinaryInteger> &moduli) {
			m_cyclotomicOrder = cyclotomic_order;
			m_moduli = moduli;
			m_rootsOfUnity = rootsOfUnity;
			calculateModulus();
			m_rootOfUnity = RootOfUnity(cyclotomic_order, m_modulus);
		}

		/**
		* Constructor with only cylotomic order and chain of moduli. Multiplied values of the chain of moduli is automatically calculated. Root of unity of the modulus is also calculated.
		*
		* @param cyclotomic_order the order of the ciphertext
		* @param &moduli is the tower of moduli
		*/
		ILDCRTParams(usint cyclotomic_order, std::vector<BigBinaryInteger> &moduli) {
			m_cyclotomicOrder = cyclotomic_order;
			m_moduli = moduli;
			calculateModulus();
			m_rootOfUnity = RootOfUnity(cyclotomic_order, m_modulus);
		}
		
		/**
		* Assignment Operator.
		*
		* @param &rhs the copied ILDCRTParams.
		* @return the resulting ILDCRTParams.
		*/
		ILDCRTParams& operator=(const ILDCRTParams &ild) {
			this->m_moduli = ild.m_moduli;
			this->m_rootsOfUnity = ild.m_rootsOfUnity;
			this->m_cyclotomicOrder = usint(ild.m_cyclotomicOrder);
			this->m_modulus = ild.m_modulus;
			this->m_rootOfUnity = ild.m_rootOfUnity;

			return *this;
		}

		// ACCESSORS

		// Get accessors
		/**
		* Get method of the order.
		*
		* @return the cyclotmic order.
		*/
		const usint GetCyclotomicOrder() const {
			return m_cyclotomicOrder;
		}
		/**
		* Get the moduli.
		*
		* @return the chain moduli.
		*/
		const std::vector<BigBinaryInteger> &GetModuli() const {
			return m_moduli;
		}
		/**
		* Get the root of unity.
		*
		* @return the roots of unity.
		*/
		const std::vector<BigBinaryInteger> &GetRootsOfUnity() const{
			return m_rootsOfUnity;
		}
		/**
		* Get modulus.
		*
		* @return the modulus.
		*/
		const BigBinaryInteger &GetModulus() const {
			return m_modulus;
		}
		/**
		* Get rootOfUnity of multipled value of chain of moduli. This value is calculated in the constructor.
		*
		* @return the rootOfUnity.
		*/
		const BigBinaryInteger &GetRootOfUnity() const {
			return m_rootOfUnity;
		}
		/**
		* Set method of the order.
		*
		* @param order the order variable.
		*/
		void SetCyclotomicOrder(const usint order) {
			m_cyclotomicOrder = order;
		}

		/**
		* Set the root of unity.
		*
		* @param &rootsOfUnity the root of unity.
		*/
		void SetRootsOfUnity(const std::vector<BigBinaryInteger> &rootsOfUnity) {
			m_rootsOfUnity = rootsOfUnity;
		}

		/**
		* Set the moduli.
		*
		* @param &moduli the moduli.
		*/

		void SetModuli(const std::vector<BigBinaryInteger> &moduli) {
			m_moduli = moduli;
		}
		/**
		* Set the moduli.
		*
		* @param &moduli the moduli.
		*/
		void SetModulus(const BigBinaryInteger &modulus) {
			m_modulus = modulus;
		}

		/**
		* Set the rootOfUnity.
		*
		* @param &rootOfUnity the rootOfUnity.
		*/
		void SetRootOfUnity(const BigBinaryInteger &rootOfUnity) {
			m_rootOfUnity = rootOfUnity;
		}


		/**
		* Destructor.
		*/
		~ILDCRTParams() {}

		//JSON FACILITY
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

			//Place holder

			return serializationMap;
		}

		//JSON FACILITY
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

			//Place holder

			return serializationMap;
		}

		//JSON FACILITY
		void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

			//Place holder

		}

	private:
		// order of cyclotomic polynomial
		usint m_cyclotomicOrder;

		// value of moduli
		std::vector<BigBinaryInteger> m_moduli;

		// primitive root unity that is used to transform from coefficient to evaluation representation and vice versa
		std::vector<BigBinaryInteger> m_rootsOfUnity;

		//Modulus that is factorized into m_moduli
		BigBinaryInteger m_modulus;

		//rootOfUnity of Modulus
		BigBinaryInteger m_rootOfUnity;

		void calculateModulus(){
		
			m_modulus = BigBinaryInteger::ONE;

			for(usint i = 0; i < m_moduli.size(); i++){
				m_modulus = m_modulus * m_moduli[i];
			}

		} 


	};

} // namespace lbcrypto ends

#endif
