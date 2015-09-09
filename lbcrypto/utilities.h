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
 * This file contains the utility function functionality.
 */

#ifndef LBCRYPTO_UTILITIES_H
#define LBCRYPTO_UTILITIES_H

#include "binint.h"
#include "binvect.h"
#include "nbtheory.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Zero Padding of Elements. 
 * Adds zeros to form a polynomial of length 2n  (corresponding to cyclotomic order m = 2n). 
 * It is used by the forward transform of ChineseRemainderTransform (a modified version of ZeroPadd will be used for the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order.
 * @return is the output of the zero padding.	  	  
 */
BigBinaryVector ZeroPadForward(const BigBinaryVector &InputPoly, usint target_order);

/**
 * Zero Pad Inverse of Elements.
 * Adds alternating zeroes to form a polynomial of length of length 2n (corresponding to cyclotomic order m = 2n). 
 * It is used by the inverse transform of ChineseRemainderTransform (a modified version of ZeroPadInverse will be used for the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order.
 * @return is the output of the zero padding.	  	  
 */
BigBinaryVector ZeroPadInverse(const BigBinaryVector &InputPoly, usint target_order);

/**
 * Determines if a number is a power of 2.
 *
 * @param input to test if it is a power of 2.
 * @return is true if the unsigned int is a power of 2.	  	  
 */
bool IsPowerOfTwo(usint Input);

} // namespace lbcrypto ends

#endif
