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
 * This code provides basic integer types for lattice crypto.
 */

#ifndef LBCRYPTO_INTTYPES_H
#define LBCRYPTO_INTTYPES_H

#include <string>
#include <stdint.h>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Type used for representing signed 8-bit integers.
 */
typedef int8_t schar;

/**
 * @brief Type used for representing signed 16-bit short integers.
 */
typedef int16_t sshort;

/**
 * @brief Type used for representing signed 32-bit integers.
 */
typedef int32_t sint;

/**
 * @brief Type used for representing unsigned 8-bit integers.
 */
typedef uint8_t uschar;

/**
 * @brief Type used for representing unsigned 16-bit short integers.
 */
typedef uint16_t usshort;

/**
 * @brief Type used for representing unsigned 32-bit integers.
 */
typedef uint32_t usint;

/**
 * @brief Type used for representing string ByteArray types.
 */
typedef std::string ByteArray;

/**
 * @brief Represents whether the polynomial ring is in EVALUATION or COEFFICIENT representation.
 */
enum Format{ EVALUATION=0, COEFFICIENT=1};


} // namespace lbcrypto ends

#endif
