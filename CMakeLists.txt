cmake_minimum_required(VERSION 3.3)
project(palisade_student_edition)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    src/crypto/ciphertext.cpp
    src/crypto/ciphertext.h
    src/crypto/lweahe.cpp
    src/crypto/lweahe.h
    src/crypto/lwecrypt.cpp
    src/crypto/lwecrypt.h
    src/crypto/lwefhe.cpp
    src/crypto/lwefhe.h
    src/crypto/lwepre.cpp
    src/crypto/lwepre.h
    src/crypto/lweshe.cpp
    src/crypto/lweshe.h
    src/crypto/pubkeylp.h
    src/encoding/padding.cpp
    src/encoding/padding.h
    src/encoding/ptxtencoding.cpp
    src/encoding/ptxtencoding.h
    src/lattice/ideals.h
    src/lattice/il2n.cpp
    src/lattice/il2n.h
    src/lattice/ringmatrix.cpp
    src/lattice/ringmatrix.h
    src/math/cpu8bit/binint.cpp
    src/math/cpu8bit/binint.h
    src/math/cpu8bit/binmat.cpp
    src/math/cpu8bit/binmat.h
    src/math/cpu8bit/binvect.cpp
    src/math/cpu8bit/binvect.h
    src/math/cpu8bit/dtstruct.cpp
    src/math/cpu8bit/dtstruct.h
    src/math/cpu8bit/mempool.cpp
    src/math/cpu8bit/mempool.h
    src/math/backend.h
    src/math/BinaryUniformGenerator.cpp
    src/math/BinaryUniformGenerator.h
    src/math/DiscreteDistributionGenerator.cpp
    src/math/DiscreteDistributionGenerator.h
    src/math/DiscreteGaussianGenerator.cpp
    src/math/DiscreteGaussianGenerator.h
    src/math/DiscreteUniformGenerator.cpp
    src/math/DiscreteUniformGenerator.h
    src/math/distrgen.h
    src/math/DistributionGenerator.cpp
    src/math/DistributionGenerator.h
    src/math/interface.h
    src/math/nbtheory.cpp
    src/math/nbtheory.h
    src/math/transfrm.cpp
    src/math/transfrm.h
    src/math/UniformIntegerGenerator.cpp
    src/math/UniformIntegerGenerator.h
    src/multilinearmap/directedencoding.h
    src/utils/bytearray.cpp
    src/utils/bytearray.h
    src/utils/inttypes.h
    src/utils/utilities.cpp
    src/utils/utilities.h
    src/Source.cpp
    Makefile)

add_executable(palisade_student_edition ${SOURCE_FILES})