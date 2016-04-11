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
		* @param &params element parameters.
		*/
		ILVectorArray2n(const ElemParams &params);

		/**
		* Copy constructor.
		*
		* @param &params element parameters.
		*/

		ILVectorArray2n(const ILVectorArray2n &element);

		// construct using an array in either Coefficient (0) or CRT format (1)
		/*
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param params the input parameters.
		* @param &levels the levels.
		*/
		ILVectorArray2n(const ILDCRTParams& params, std::vector<ILVector2n> &levels, Format format);

		// construct using an array in either Coefficient (0) or CRT format (1)
		/*
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param params the input parameters.
		* @param &levels the levels.
		*/
		ILVectorArray2n(const bool b, DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format);
		/*
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param element the input parameter to build ILVectorArray2n from one vector for double-CRT representation.
		*/
		ILVectorArray2n(ILVector2n element, const ILDCRTParams& params, Format format);


		/**
		* Constructor based on full methods.
		*
		* @param &dgg the input discrete Gaussian Generator.
		* @param &params the input params.
		* @param &format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format = EVALUATION);

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		ILVectorArray2n& operator=(const ILVectorArray2n &rhs);


		// DESTRUCTORS
		/**
		* Destructor.
		*/
		~ILVectorArray2n();

		// Get accessors
		/**
		* Get method of the vector values.
		*
		* @returns an ILVector2n.
		*/
		ILVector2n GetValues(usint i) const;


		/**
		* Get method of the vector values.
		*
		* @returns values.
		*/
		std::vector<ILVector2n> GetValues() const;

		/**
		* Get method of the format.
		*
		* @return the format.
		*/
		Format GetFormat() const;

		/**
		* Get method of the parameter set.
		*
		* @return the parameter set.
		*/

		const ILDCRTParams &GetParams() const;

		/**
		* Set method of the values.
		*
		* @param &params is the ILDCRTParams.
		*/
		void SetParams(const ElemParams &params);

		// Set accessors

		/**
		* Set method of the values.
		*
		* @param values is the set of values of the vector.
		*/
		void SetValues(std::vector<ILVector2n>& values, Format format);

		/**
		Print values
		*/
		void PrintValues() const;

		/**
		Plus One
		*/
		void ModularOne();


		/**
		Make ILVectorArray2n Sparse for SHE KeyGen operations
		*/
		void MakeSparse(const BigBinaryInteger &modulus);


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
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return is the return value of the modulus by 2, also the least significant bit.
		*/
		ILVectorArray2n ModByTwo() const;

		// addition operation
		/*
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

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator+=(const ILVectorArray2n &element);

		// automorphism operation
		/**
		* Performs an automorphism transform operation and returns the result.
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		ILVectorArray2n AutomorphismTransform(const usint &i) const {return ILVectorArray2n(*this);};


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
		ILVectorArray2n Mod(const BigBinaryInteger & modulus) const;

		/**
		*This function returns the interpolated vectors
		*/

		// get digit for a specific based - used for PRE scheme
		/**
		* Get digit for a specific base.  Gets a binary polynomial from a given polynomial.  From every coefficient, it extracts the same digit.  Used in bit decomposition/relinearization operations.
		*
		* @param index is the index to get.
		* @param base is the base the result should be in.
		* @return is the result.
		*/
		ILVectorArray2n GetDigitAtIndexForBase(usint index, usint base) const;

		ILVectorArray2n Decompose(const ElemParams &decomposedParams) const;

		/**
		* Drops the last tower of ILVectorArray2n and adjusts parameters.
		*/
		void DropTower(usint index);

		/**
		* ModReduces
		*/
		void ModReduce();

		ILVector2n InterpolateIlArrayVector2n();

		usint GetLength() const;

		
		// convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT
		/**
		* Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
		*/
		void SwitchFormat();

		/**
		Set to Test value
		*/
		void SetToTestValue() ;

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
		* @return map passed in.
		*/
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

		//JSON FACILITY
		/**
		* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
		* Invokes nested serialization of BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
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

		private:BigBinaryInteger CalculateInterpolationSum2(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors, usint index);

		private:BigBinaryInteger CalculateInterpolationSum(std::vector<BigBinaryInteger> vectorOfBigInts, usint index);

		/*
		Helper method for chinese remainder interpolatiom
		*/

		private:std::vector<std::vector<BigBinaryInteger>> BuildChineseRemainderInterpolationVector(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors);

		/*
		Helper method for chinese remainder interpolatiom
		*/

		private:BigBinaryInteger CalculateChineseRemainderInterpolationCoefficient(usint i);

	    /*
		*This function is a helper function that applies a modulus to all IlVector2n's so they don't wrap their respective modulus
		*/
	
	private:void ChangeModuliOfIlVectorsToMatchDBLCRT();

	/*
	*helper function for chinese remainder interpolation
	*/
	private:std::vector<BigBinaryInteger> BuildChineseRemainderInterpolationVectorForRow(usint i);

			/*This function takes in a row and a vector of vector of BigBinaryIntegers and calculates the sum of each
			row, module the value set by the CRI formula*/
			/*This method calculates the value for CRI*/
	private:BigBinaryInteger CalculatInterpolateModulu(BigBinaryInteger value, usint index);


	private:
		// array of vectors used for double-CRT presentation
		std::vector<ILVector2n> m_vectors;

		// parameters for the ideal lattice: cyclotomic order and ciphertext modulus factors
		ILDCRTParams m_params;

		// 0 for coefficient and 1 for evaluation format
		Format m_format;

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
