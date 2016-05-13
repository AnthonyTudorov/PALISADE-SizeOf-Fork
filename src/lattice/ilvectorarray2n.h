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
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
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
* This code provides basic lattice ideal manipulation functionality.
*/

#ifndef LBCRYPTO_LATTICE_IL2VECTORARRAY2N_H
#define LBCRYPTO_LATTICE_IL2VECTORARRAY2N_H

#include <vector>
#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"
#include "../lattice/ilvector2n.h"
#include "../math/nbtheory.h"
#include "../math/transfrm.h"
//#include "../encoding/ptxtencoding.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	* @brief Ideal lattice in the double-CRT representation.  This is not fully implemented and is currently only stubs.
	*/
	class ILVectorArray2n : public ILElement
	{
	public:

		// CONSTRUCTORS


		/**
		* Constructor that initializes nothing.
		*/
		ILVectorArray2n();
		
		/**
		* Constructor that initializes parameters.
		*
		* @param &params parameter set required for ILVectorArray2n.
		*/
		ILVectorArray2n(const ElemParams &params);

		/**
		* Copy constructor.
		*
		* @param &element ILVectorArray2n to copy from
		*/

		ILVectorArray2n(const ILVectorArray2n &element);
		/**
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param &params parameter set required for ILVectorArray2n.
		* @param &levels vector of ILVector2ns which correspond to each tower of ILVectorArray2n.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const ElemParams &params, const std::vector<ILVector2n> &levels, Format format = EVALUATION);
		/**
		* Construct using a single ILVector2n in either Coefficient (0) or CRT format (1).
		*
		* @param &element ILVector2n to build other towers from.
		* @param &params parameter set required for ILVectorArray2n.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const ILVector2n &element, const ElemParams &params, Format format = EVALUATION);
		/**
		* Constructor based on full methods.
		*
		* @param &dgg the input discrete Gaussian Generator.
		* @param &params parameter set required for ILVectorArray2n.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format = EVALUATION);


		// DESTRUCTORS
		/**
		* Destructor.
		*/
		~ILVectorArray2n();

	
		// Get accessors
		/**
		* Get method of individual towers.
		*
		* @param i index of tower to be returned.
		* @returns a reference to the ILVector2n at index i.
		*/
		const ILVector2n &GetValues(usint i) const;

		/**
		* Set method of the values.
		*
		* @param &levels vector of ILVector2ns which correspond to each tower of ILVectorArray2n.
		* @param format the input format of ILVectors. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		void SetValues(const std::vector<ILVector2n> &levels, Format format);

		/**
		* Set method of the values.
		*
		* @param &params is the ILDCRTParams.
		*/
		void SetParams(const ElemParams &params);

		/**
		* Get method of the tower length.
		*
		* @return the length of the tower.
		*/
		usint GetLength() const;
		
		/**
		* Get method that returns a vector of all towers.
		*
		* @returns values.
		*/
		const std::vector<ILVector2n>& GetValues() const;

		/**
		* Get method of the parameter set.
		*
		* @return the parameter set.
		*/
		const ElemParams &GetParams() const;

		/**
		* Get method of the format.
		*
		* @return the format.
		*/
		Format GetFormat() const;
		
		/**
		* Get digit for a specific base.  Gets a binary polynomial from a given polynomial.  From every coefficient, it extracts the same digit.  Used in bit decomposition/relinearization operations.
		*
		* @param index is the index to get.
		* @param base is the base the result should be in.
		* @return is the result.
		*/
		ILVectorArray2n GetDigitAtIndexForBase(usint index, usint base) const;

		/**
		* Access method of the parameter set non-const.
		*
		* @return the parameter set non-const.
		*/

		ElemParams& AccessParams();

		/**
		* Prints values of each tower
		*/
		void PrintValues() const;

		/**
		* Adds one to every entry in every tower.
		*/
		void AddILElementOne();
		/**
		* Make ILVectorArray2n Sparse for SHE KeyGen operations. Sets every index not equal to zero mod the wFactor to zero for every tower.
		*
		* @param &wFactor ratio between the original ILVectorArray2n's ring dimension and the new ring dimension.
		*/
		void MakeSparse(const BigBinaryInteger &wFactor);

		// SCALAR OPERATIONS

		// multiplicative inverse operation
		/**
		* Performs a multiplicative inverse operation and returns the result.
		*
		* @return is the result of the multiplicative inverse.
		*/
		ILVectorArray2n MultiplicativeInverse() const;

		/**
		* Scalar addition - add an element to all entries.
		*
		* @param &element is the element to add entry-wise.
		* @return is the return of the addition operation.
		*/
		ILVectorArray2n Plus(const BigBinaryInteger &element) const;

		/**
		* Scalar subtraction - subtract an element to all entries.
		*
		* @param &element is the element to subtract entry-wise.
		* @return is the return value of the minus operation.
		*/
		ILVectorArray2n Minus(const BigBinaryInteger &element) const;

		/**
		* Scalar multiplication - multiply all entries.
		*
		* @param &element is the element to multiply entry-wise.
		* @return is the return value of the times operation.
		*/

		ILVectorArray2n Times(const BigBinaryInteger &element) const;

		/**
		* Modulus - perform a modulus operation.
		*
		* @param modulus is the modulus to use.
		* @return is the return value of the modulus.
		*/
		ILVectorArray2n Mod(const BigBinaryInteger &modulus) const;

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return is the return value of the modulus by 2, also the least significant bit.
		*/
		ILVectorArray2n ModByTwo() const;

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator+=(const BigBinaryInteger &element);

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator-=(const BigBinaryInteger &element);

		//VECTOR OPERATIONS

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied ILVectorArray2n.
		* @return the resulting ILVectorArray2n.
		*/
		ILVectorArray2n& operator=(const ILVectorArray2n &rhs);

		/**
		* Equal operator compares this ILVectorArray2n to the specified ILVectorArray2n
		*
		* @param &rhs is the specified ILVectorArray2n to be compared with this ILVectorArray2n.
		* @return true if this ILVectorArray2n represents the same values as the specified ILVectorArray2n, false otherwise
		*/
		inline bool operator==(const lbcrypto::ILVectorArray2n &rhs) const {
            if (this->GetFormat() != rhs.GetFormat()) {
                return false;
            }
            if (m_vectors != rhs.GetValues()) {
                return false;
            }

		    const ILDCRTParams &castedObj = dynamic_cast<const ILDCRTParams&>(rhs.GetParams());

			if(const_cast<ILDCRTParams&>(m_params) != castedObj) { //why is it seeing m_params as const???!!
				return false;
			}
            return true;
        }

		/**
		* Not equal operator compares this ILVectorArray2n to the specified ILVectorArray2n
		*
		* @param &rhs is the specified ILVectorArray2n to be compared with this ILVectorArray2n.
		* @return true if this ILVectorArray2n represents the same values as the specified ILVectorArray2n, false otherwise
		*/
        inline bool operator!=(const lbcrypto::ILVectorArray2n &rhs) const {
            return !(*this == rhs);
        }
		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator+=(const ILVectorArray2n &element);

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator-=(const ILVectorArray2n &element);

		// automorphism operation
		/**
		* Performs an automorphism transform operation and returns the result.
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		ILVectorArray2n AutomorphismTransform(const usint &i) const {return ILVectorArray2n(*this);};
		//addition operation
		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		ILVectorArray2n Plus(const ILVectorArray2n &element) const;

		// multiplication operation - 
		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		ILVectorArray2n Times(const ILVectorArray2n &element) const;
		// subtraction operation
		/**
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract with.
		* @return is the result of the subtraction.
		*/
		ILVectorArray2n Minus(const ILVectorArray2n &element) const;

		// OTHER FUNCTIONS AND UTILITIES 
		/**
		* Interleaves values in each tower with odd indices being all zeros.
		*/
		void Decompose();
		/**
		* @param index is the index of the tower to be dropped.
		* Drops the last tower of ILVectorArray2n and adjusts parameters.
		*/
		void DropTower(usint index);
		/**
		* ModReduces reduces the ILVectorArray2n's composite modulus by dropping the last modulus from the chain of moduli.
		*/
		void ModReduce();
		/**
		* Interpolates the ILVectorArray2n to an ILVector2n based on the Chinese Remainder Transform Interpolation.
		*
		* @return the ILVector2n representation of the ILVectorArray2n.
		*/

		ILVector2n InterpolateIlArrayVector2n() const;
		
		/**
		* Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
		*/
		void SwitchFormat();

		/**
		* Determines if inverse exists
		*
		* @return is the Boolean representation of the existence of multiplicative inverse.
		*/
		bool InverseExists() const;

		//JSON FACILITY
		/**
		* Implemented by this object only for inheritance requirements of abstract class Serializable.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @param flag TODO.
		* @return map passed in.
		*/
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

		//JSON FACILITY
		/**
		* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
		* Invokes nested serialization of BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @param fileFlag TODO.
		* @return map updated with the attribute name value pairs required to serialize this object.
		*/
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

		//JSON FACILITY
		/**
		* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
		* Invokes nested deserialization of BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		*/
		void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);



	private:
		// array of vectors used for double-CRT presentation
		std::vector<ILVector2n> m_vectors;

		// parameters for the ideal lattice: cyclotomic order and ciphertext modulus factors
		ILDCRTParams m_params;

		// 0 for coefficient and 1 for evaluation format
		Format m_format;

		BigBinaryInteger CalculateInterpolationSum(usint index) const;

		/*Helper method for chinese remainder interpolatiom*/
		BigBinaryInteger CalculateChineseRemainderInterpolationCoefficient(usint i) const;

	};

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator*(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.Times(b); }

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator*(const lbcrypto::BigBinaryInteger &b, const lbcrypto::ILVectorArray2n &a) { return a.Times(b); }

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator*(const lbcrypto::ILVectorArray2n &b,const lbcrypto::BigBinaryInteger &a) { return b.Times(a); }

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator+(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.Plus(b); }

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator+(const lbcrypto::ILVectorArray2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Plus(b); }
} // namespace lbcrypto ends

#endif
