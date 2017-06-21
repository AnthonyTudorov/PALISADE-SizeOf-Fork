/**
 * @file ildcrt2n.h Represents integer lattice elements with double-CRT and power-of-2 dimensions.
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

#ifndef LBCRYPTO_LATTICE_IL2VECTORARRAY2N_H
#define LBCRYPTO_LATTICE_IL2VECTORARRAY2N_H

#include <vector>
#include <string>

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"
#include "../lattice/ilvector2n.h"
#include "../math/nbtheory.h"
#include "../math/transfrm.h"
#include "../math/distrgen.h"

namespace lbcrypto
{

/**
* @brief Ideal lattice for the double-CRT representation.
* The implementation contains a vector of underlying native-integer lattices
* The double-CRT representation of polynomials is a common optimization for lattice encryption operations.
* Basically, it allows large-modulus polynamials to be represented as multiple smaller-modulus polynomials.
* The double-CRT representations are discussed theoretically here:
*   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology – CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin, Heidelberg
*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
class ILDCRTImpl : public ILElement< ILDCRTImpl<ModType,IntType,VecType,ParmType>,ModType,IntType,VecType>
{
public:
	typedef ParmType Params;
	typedef IntType Integer;
	typedef VecType Vector;

	typedef ILDCRTImpl<ModType,IntType,VecType,ParmType> ILVectorArrayType;
	typedef DiscreteGaussianGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector> DggType;
	typedef DiscreteUniformGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector> DugType;
	typedef TernaryUniformGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector> TugType;
	typedef BinaryUniformGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector> BugType;

	// this class contains an array of these:
	typedef ILVectorImpl<native_int::BinaryInteger,native_int::BinaryInteger,native_int::BinaryVector,native_int::ILParams> ILVectorType;
	typedef ILVectorImpl<ModType,IntType,VecType,ILParams> ILVectorLargeType;

	static const std::string GetElementName() {
		return "ILDCRTImpl";
	}

	// CONSTRUCTORS

	/**
	* @brief Constructor that initialized m_format to EVALUATION and calls m_params to nothing
	*/
	ILDCRTImpl();

	/**
	* Constructor that initializes parameters.
	*
	*@param params parameter set required for ILDCRT2n.
	*@param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*@param initializeElementToZero
	*/
	ILDCRTImpl(const shared_ptr<ParmType> params, Format format = EVALUATION, bool initializeElementToZero = false);

	// FIXME should be private?
	void fillVectorArrayFromBigVector(const ILVector2n& element, const shared_ptr<ParmType> params);

	/**
	* @brief Constructor based on discrete Gaussian generator.
	*
	* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the ILDCRT2n with random numbers.
	* @param params parameter set required for ILDCRT2n.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	ILDCRTImpl(const DggType &dgg, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	* @brief Constructor based on binary Gaussian generator. This is not implemented. Will throw a logic_error.
	*
	* @param &bug the input binary uniform generator. The bug will be the seed to populate the towers of the ILDCRT2n with random numbers.
	* @param params parameter set required for ILDCRT2n.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	ILDCRTImpl(const BugType &bug, const shared_ptr<ParmType> params, Format format = EVALUATION) {
		throw std::logic_error("Cannot use BinaryUniformGenerator with ILDCRT2n; not implemented");
	}

	/**
	* @brief Constructor based on binary Gaussian generator. This is not implemented. Will throw a logic_error.
	*
	* @param &tug the input ternary uniform generator. The bug will be the seed to populate the towers of the ILDCRT2n with random numbers.
	* @param params parameter set required for ILDCRT2n.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	ILDCRTImpl(const TugType &tug, const shared_ptr<ParmType> params, Format format = EVALUATION) {
		throw std::logic_error("Cannot use TernaryUniformGenerator with ILDCRT2n; not implemented");
	}

	/**
	* @brief Constructor based on full methods.
	*
	* @param &dug the input discrete Uniform Generator.
	* @param params the input params.
	* @param &format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	ILDCRTImpl(DugType &dug, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	* @brief Construct using a single ILVector2n. The ILVector2n is copied into every tower. Each tower will be reduced to it's corresponding modulus  via GetModuli(at tower index). The format is derived from the passed in ILVector2n.
	*
	* @param &element ILVector2n to build other towers from.
	* @param params parameter set required for ILDCRT2n.
	*/
	ILDCRTImpl(const ILVector2n &element, const shared_ptr<ParmType> params);

	/**
	* @brief Construct using an tower of ILVectro2ns. The params and format for the ILDCRT2n will be derived from the towers.
	*
	* @param &towers vector of ILVector2ns which correspond to each tower of ILDCRT2n.
	*/
	ILDCRTImpl(const std::vector<ILVectorType> &elements);

	/**
	* @brief Copy constructor.
	*
	* @param &element ILDCRT2n to copy from
	*/
	ILDCRTImpl(const ILVectorArrayType &element);

	/**
	* @brief Move constructor.
	*
	* @param &&element ILDCRT2n to move from
	*/
	ILDCRTImpl(const ILVectorArrayType &&element);

	//CLONE OPERATIONS
	/**
	 * @brief Clone the object by making a copy of it and returning the copy
	 * @return new Element
	 */
	ILVectorArrayType Clone() const {
		return std::move(ILDCRTImpl(*this));
	}

	/**
	 * @brief Clone the object, but have it contain nothing
	 * @return new Element
	 */
	ILVectorArrayType CloneEmpty() const {
		return std::move( ILDCRTImpl() );
	}

	/**
	* @brief Clone method creates a new ILDCRT2n and clones only the params. The tower values are empty. The tower values can be filled by another process/function or initializer list.
	*/
	ILVectorArrayType CloneParametersOnly() const;

	/**
	* @brief Clone with noise.  This method creates a new ILDCRT2n and clones the params. The tower values will be filled up with noise based on the discrete gaussian.
	*
	* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the ILDCRT2n with random numbers.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	ILVectorArrayType CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format = EVALUATION) const;

	/**
	* @brief Destructor.
	*/
	~ILDCRTImpl();

	//GETTERS

	/**
	 * @brief returns the parameters of the element.
	 * @return the element parameter set.
	 */
	const shared_ptr<ParmType> GetParams() const {
		return m_params;
	}

	/**
	 * @brief returns the element's cyclotomic order
	 * @return returns the cyclotomic order of the element.
	 */
	const usint GetCyclotomicOrder() const {
		return m_params->GetCyclotomicOrder();
	}

	/**
	 * @brief returns the element's ring dimension
	 * @return returns the ring dimension of the element.
	 */
	const usint GetRingDimension() const {
		return m_params->GetRingDimension();
	}

	/**
	 * @brief returns the element's modulus
	 * @return returns the modulus of the element.
	 */
	const ModType &GetModulus() const {
		return m_params->GetModulus();
	}

	/**
	 * @brief returns the element's root of unity.
	 * @return the element's root of unity.
	 */
	const IntType &GetRootOfUnity() const {
		static IntType t(0);
		return t;
	}

	/**
	* @brief Get method for length of each component element.
	* NOTE assumes all components are the same size.
	*
	* @return length of the component element
	*/
	usint GetLength() const {
		if( m_vectors.size() == 0 )
			return 0;

		return m_vectors[0].GetValues().GetLength();
	}

	/**
	* @brief Get method of individual compoment elements.
	*
	* @param i index of component element to be returned.
	* @returns a reference to the component element at index i.
	*/
	const ILVectorType &GetElementAtIndex(usint i) const;

	/**
	* @brief Get method of the number of component elements, also known as the number of towers.
	*
	* @return the number of component elements.
	*/
	usint GetNumOfElements() const;

	/**
	* @brief Get method that returns a vector of all component elements.
	*
	* @returns a vector of the component elements.
	*/
	const std::vector<ILVectorType>& GetAllElements() const;

	/**
	* @brief Get method of the format.
	*
	* @return the format, either COEFFICIENT or EVALUATION
	*/
	Format GetFormat() const;

	/**
	 * @brief Write the element as \f$ \sum\limits{i=0}^{\lfloor {\log q/base} \rfloor} {(base^i u_i)} \f$ and
	 * return the vector of \f$ \left\{u_0, u_1,...,u_{\lfloor {\log q/base} \rfloor} \right\} \in R_{{base}^{\lceil {\log q/base} \rceil}} \f$;
	 * This is used as a subroutine in the relinearization procedure.
	 *
	 * @param baseBits is the number of bits in the base, i.e., \f$ base = 2^{baseBits} \f$.
	 * @return is the pointer where the base decomposition vector is stored
	 */
	std::vector<ILVectorArrayType> BaseDecompose(usint baseBits, bool evalModeAnswer=true) const ;

	/**
	 * @brief Generate a vector of ILVectorImpl's as \f$ \left\{x, {base}*x, {base}^2*x, ..., {base}^{\lfloor {\log q/{base}} \rfloor} \right\}*x \f$,
	 * where \f$ x \f$ is the current ILVectorImpl object;
	 * used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element.
	 *
	 * @param baseBits is the number of bits in the base, i.e., \f$ base = 2^{baseBits} \f$.
	 * @return is the pointer where the base decomposition vector is stored
	 */
	std::vector<ILVectorArrayType> PowersOfBase(usint baseBits) const ;


	//VECTOR OPERATIONS

	/**
	* @brief Assignment Operator.
	*
	* @param &rhs the copied element.
	* @return the resulting element.
	*/
	const ILVectorArrayType& operator=(const ILVectorArrayType &rhs);

	/**
	* @brief Move Assignment Operator.
	*
	* @param &rhs the copied element.
	* @return the resulting element.
	*/
	const ILVectorArrayType& operator=(ILVectorArrayType &&rhs);

	/**
	* @brief Initalizer list
	*
	* @param &rhs the list to initalized the element.
	* @return the resulting element.
	*/
	ILVectorArrayType& operator=(std::initializer_list<sint> rhs);

	/**
	 * @brief Unary minus on a element.
	 * @return additive inverse of the an element.
	 */
	ILVectorArrayType operator-() const {
		ILVectorArrayType all0(this->GetParams(), this->GetFormat(), true);
		return all0 - *this;
	}

	/**
	* @brief Equality operator.
	*
	* @param &rhs is the specified element to be compared with this element.
	* @return true if this element represents the same values as the specified element, false otherwise
	*/
	bool operator==(const ILVectorArrayType &rhs) const;

	/**
	* @brief Performs an entry-wise addition over all elements of each tower with the towers of the element on the right hand side.
	*
	* @param &rhs is the element to add with.
	* @return is the result of the addition.
	*/
	const ILVectorArrayType& operator+=(const ILVectorArrayType &rhs);

	/**
	* @brief Performs an entry-wise subtraction over all elements of each tower with the towers of the element on the right hand side.
	*
	* @param &rhs is the element to subtract from.
	* @return is the result of the addition.
	*/
	const ILVectorArrayType& operator-=(const ILVectorArrayType &rhs);

	/**
	* @brief Permutes coefficients in a polynomial. Moves the ith index to the first one, it only supports odd indices.
	*
	* @param &i is the element to perform the automorphism transform with.
	* @return is the result of the automorphism transform.
	*/
	ILVectorArrayType AutomorphismTransform(const usint &i) const {
		return ILVectorArrayType(*this);
	}

	/**
	* @brief Performs an addition operation and returns the result.
	*
	* @param &element is the element to add with.
	* @return is the result of the addition.
	*/
	ILVectorArrayType Plus(const ILVectorArrayType &element) const;

	/**
	* @brief Performs a multiplication operation and returns the result.
	*
	* @param &element is the element to multiply with.
	* @return is the result of the multiplication.
	*/
	ILVectorArrayType Times(const ILVectorArrayType &element) const;

	/**
	* @brief Performs a subtraction operation and returns the result.
	*
	* @param &element is the element to subtract from.
	* @return is the result of the subtraction.
	*/
	ILVectorArrayType Minus(const ILVectorArrayType &element) const;

	//SCALAR OPERATIONS

	/**
	* @brief Scalar addition - add an element to the first index of each tower.
	*
	* @param &element is the element to add entry-wise.
	* @return is the result of the addition operation.
	*/
	ILVectorArrayType Plus(const IntType &element) const;

	/**
	* @brief Scalar subtraction - subtract an element to all entries.
	*
	* @param &element is the element to subtract entry-wise.
	* @return is the return value of the minus operation.
	*/
	ILVectorArrayType Minus(const IntType &element) const;

	/**
	* @brief Scalar multiplication - multiply all entries.
	*
	* @param &element is the element to multiply entry-wise.
	* @return is the return value of the times operation.
	*/
	ILVectorArrayType Times(const IntType &element) const;

	/**
	* @brief Scalar multiplication followed by division and rounding operation - operation on all entries.
	*
	* @param &p is the element to multiply entry-wise.
	* @param &q is the element to divide entry-wise.
	* @return is the return value of the multiply, divide and followed by rounding operation.
	*/
	ILVectorArrayType MultiplyAndRound(const IntType &p, const IntType &q) const;

	/**
	* @brief Scalar division followed by rounding operation - operation on all entries.
	*
	* @param &q is the element to divide entry-wise.
	* @return is the return value of the divide, followed by rounding operation.
	*/
	ILVectorArrayType DivideAndRound(const IntType &q) const;

	/**
	* @brief Performs a negation operation and returns the result.
	*
	* @return is the result of the negation.
	*/
	ILVectorArrayType Negate() const;

	const ILVectorArrayType& operator+=(const IntType &element) {
		return *this = Plus(element);
	}

	/**
	* @brief Performs a subtraction operation and returns the result.
	*
	* @param &element is the element to subtract from.
	* @return is the result of the subtraction.
	*/
	const ILVectorArrayType& operator-=(const IntType &element) {
		return *this = Minus(element);
	}

	/**
	* @brief Performs a multiplication operation and returns the result.
	*
	* @param &element is the element to multiply by.
	* @return is the result of the subtraction.
	*/
	const ILVectorArrayType& operator*=(const IntType &element);

	/**
	* @brief Performs an multiplication operation and returns the result.
	*
	* @param &element is the element to multiply with.
	* @return is the result of the multiplication.
	*/
	const ILVectorArrayType& operator*=(const ILVectorArrayType &element);

	// multiplicative inverse operation
	/**
	* @brief Performs a multiplicative inverse operation and returns the result.
	*
	* @return is the result of the multiplicative inverse.
	*/
	ILVectorArrayType MultiplicativeInverse() const;

	/**
	* @brief Perform a modulus by 2 operation.  Returns the least significant bit.
	*
	* @return is the resulting value.
	*/
	ILVectorArrayType ModByTwo() const;

	/**
	* @brief Modulus - perform a modulus operation. Does proper mapping of [-modulus/2, modulus/2) to [0, modulus)
	*
	* @param modulus is the modulus to use.
	* @return is the return value of the modulus.
	*/
	ILVectorArrayType SignedMod(const IntType &modulus) const {
		throw std::logic_error("SignedMod of an IntType not implemented on ILDCRT2n");
	}

	// OTHER FUNCTIONS AND UTILITIES

	/**
	* @brief Get method that should not be used
	*
	* @return will throw a logic_error
	*/
	const VecType &GetValues() const {
		throw std::logic_error("GetValues not implemented on ILDCRT2n");
	}

	/**
	* @brief Set method that should not be used, will throw an error.
	*
	* @param &values
	* @param format
	*/
	void SetValues(const VecType &values, Format format) {
		throw std::logic_error("SetValues not implemented on ILDCRT2n");
	}

	/**
	* @brief Prints values of each tower
	*/
	void PrintValues() const;

	/**
	* @brief Adds "1" to every entry in every tower.
	*/
	void AddILElementOne();

	/**
	* @brief Add uniformly random values to all components except for the first one
	*/
	ILVectorArrayType AddRandomNoise(const IntType &modulus) const {
		throw std::logic_error("AddRandomNoise is not currently implemented for ILVectorArray2n");
	}

	/**
	* @brief Make ILDCRT2n Sparse. Sets every index of each tower not equal to zero mod the wFactor to zero.
	*
	* @param &wFactor ratio between the sparse and none-sparse values.
	*/
	void MakeSparse(const uint32_t &wFactor);

	/**
	* @brief Performs ILVector2n::Decompose on each tower and adjusts the ILDCRT2n.m_parameters accordingly. This method also reduces the ring dimension by half.
	*/
	void Decompose();

	/**
	* @brief Returns true if ALL the tower(s) are empty.
	* @return true if all towers are empty
	*/
	bool IsEmpty() const;

	/**
	* @brief Drops the last element in the double-CRT representation. The resulting ILDCRT2n element will have one less tower.
	*/
	void DropLastElement();

	/**
	* @brief ModReduces reduces the ILDCRT2n element's composite modulus by dropping the last modulus from the chain of moduli as well as dropping the last tower.
	*
	* @param plaintextModulus is the plaintextModulus used for the ILDCRT2n
	*/
	void ModReduce(const IntType &plaintextModulus);

	/**
	* @brief Interpolates the ILDCRT2n to an ILVector2n based on the Chinese Remainder Transform Interpolation.
	* and then returns an ILDCRT2n with that single element
	*
	* @return the interpolated ring element embeded into ILDCRT2n.
	*/
	ILVector2n CRTInterpolate() const;

	/**
	* @brief Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
	*/
	void SwitchFormat();

	/**
	* @brief Switch modulus and adjust the values
	*
	* @param &modulus is the modulus to be set
	* @param &rootOfUnity is the corresponding root of unity for the modulus
	* @param &modulusArb is the modulus used for arbitrary cyclotomics CRT
	* @param &rootOfUnityArb is the corresponding root of unity for the modulus
	* ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus
	*/
	void SwitchModulus(const IntType &modulus, const IntType &rootOfUnity, const IntType &modulusArb = IntType::ZERO, const IntType &rootOfUnityArb = IntType::ZERO) {
		throw std::logic_error("SwitchModulus not implemented on ILVectorArray2n");
	}

	/**
	* @brief Switch modulus at tower i and adjust the values
	*
	* @param index is the index for the tower
	* @param &modulus is the modulus to be set
	* @param &rootOfUnity is the corresponding root of unity for the modulus
	* ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus
	*/
	void SwitchModulusAtIndex(usint index, const IntType &modulus, const IntType &rootOfUnity);

	/**
	* @brief Determines if inverse exists
	*
	* @return is the Boolean representation of the existence of multiplicative inverse.
	*/
	bool InverseExists() const;

	//JSON FACILITY
	/**
	* @brief Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
	* Invokes nested serialization of Vector.
	*
	* @param serializationMap stores this object's serialized attribute name value pairs.
	* @return true on success
	*/
	bool Serialize(Serialized* serObj) const;

	/**
	* @brief Populate the object from the deserialization of the Setialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool Deserialize(const Serialized& serObj);

	/**
	 * @brief ostream operator
	 * @param os the input preceding output stream
	 * @param vec the element to add to the output stream.
	 * @return a resulting concatenated output stream
	 */
	friend inline std::ostream& operator<<(std::ostream& os, const ILVectorArrayType& vec) {
		for( usint i=0; i<vec.GetAllElements().size(); i++ ) {
			os << i << ": ";
			os << vec.GetAllElements()[i] << std::endl;
		}
		return os;
	}
	/**
	 * @brief Element-element addition operator.
	 * @param a first element to add.
	 * @param b second element to add.
	 * @return the result of the addition operation.
	 */
	friend inline ILVectorArrayType operator+(const ILVectorArrayType &a, const ILVectorArrayType &b) {
		return a.Plus(b);
	}
	/**
	 * @brief Element-integer addition operator.
	 * @param a first element to add.
	 * @param b integer to add.
	 * @return the result of the addition operation.
	 */
	friend inline ILVectorArrayType operator+(const ILVectorArrayType &a, const IntType &b) {
		return a.Plus(b);
	}
	
	/**
	 * @brief Integer-element addition operator.
	 * @param a integer to add.
	 * @param b element to add.
	 * @return the result of the addition operation.
	 */
	friend inline ILVectorArrayType operator+(const IntType &a, const ILVectorArrayType &b) {
		return b.Plus(a);
	}
	
	/**
	 * @brief Element-element subtraction operator.
	 * @param a element to subtract from.
	 * @param b element to subtract.
	 * @return the result of the subtraction operation.
	 */
	friend inline ILVectorArrayType operator-(const ILVectorArrayType &a, const ILVectorArrayType &b) {
		return a.Minus(b);
	}
	
	/**
	 * @brief Element-integer subtraction operator.
	 * @param a element to subtract from.
	 * @param b integer to subtract.
	 * @return the result of the subtraction operation.
	 */
	friend inline ILVectorArrayType operator-(const ILVectorArrayType &a, const IntType &b) {
		return a.Minus(b);
	}
	
	/**
	 * @brief Element-element multiplication operator.
	 * @param a element to multiply.
	 * @param b element to multiply.
	 * @return the result of the multiplication operation.
	 */
	friend inline ILVectorArrayType operator*(const ILVectorArrayType &a, const ILVectorArrayType &b) {
		return a.Times(b);
	}
	
	/**
	 * @brief Element-integer multiplication operator.
	 * @param a element to multiply.
	 * @param b integer to multiply.
	 * @return the result of the multiplication operation.
	 */
	friend inline ILVectorArrayType operator*(const ILVectorArrayType &a, const IntType &b) {
		return a.Times(b);
	}
	
	/**
	 * @brief Integer-element multiplication operator.
	 * @param a integer to multiply.
	 * @param b element to multiply.
	 * @return the result of the multiplication operation.
	 */
	friend inline ILVectorArrayType operator*(const IntType &a, const ILVectorArrayType &b) {
		return b.Times(a);
	}

private:
	shared_ptr<ParmType> m_params;

	// array of vectors used for double-CRT presentation
	std::vector<ILVectorType> m_vectors;

	// Either Format::EVALUATION (0) or Format::COEFFICIENT (1)
	Format m_format;
};

} // namespace lbcrypto ends

namespace lbcrypto
{

typedef ILDCRTImpl<BigBinaryInteger, BigBinaryInteger, BigBinaryVector, ILDCRTParams<BigBinaryInteger>> ILDCRT2n;

}



#endif
