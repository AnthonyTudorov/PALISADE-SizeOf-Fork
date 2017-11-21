# Sampling in PALISADE

PALISADE library offers various methods for sampling from discrete Gaussian distributions. The methods are implemented in both [DiscreteGaussianGenerator](./discretegaussiangenerator.h) and [DiscreteGaussianGeneratorGeneric](./discretegaussiangeneratorgeneric.h) classes, which have their specific uses. All of the samplers discussed has been tested in [GLITCH Discrete Gaussian Testing Suite](https://eprint.iacr.org/2017/438.pdf) and no problems/abnormalities have been found. 

## Samplers in DiscreteGaussianGenerator

The class [DiscreteGaussianGenerator](./discretegaussiangenerator.h) was the first class implemented for integer sampling, therefore it contains mainly algorithms that center around rejection.

* __Rejection Sampling:__ Rejection sampling is defined in section 4.1 of the paper [Trapdoors for Hard Lattices and
New Cryptographic Constructions](https://eprint.iacr.org/2007/432.pdf). It is used in the method GenerateInteger. Rejection sampling can be used any arbitrary center and standard deviation without any precomputations. However, it has high rejection rate and is vulnerable to timing attacks. It is currently not used, 

* __Karney's Method:__ Karney's method is defined as Algorithm D in the paper [Sampling exactly from the normal distribution](https://arxiv.org/pdf/1303.6257.pdf), which is an improvement on the traditional rejection sampling. It is used in the method GenerateIntegerKarney. Like the rejection sampling, it can be used for arbitrary center and standard deviation without any precomputations. It has a smaller rejection rate than the traditional sampling but it is still prone to timing attacks.

* __Peikert's Inversion Method:__ Peikert's inversion method discussed in section 4.1 of the paper [An Efficient and Parallel Gaussian Sampler for Lattices](https://eprint.iacr.org/2010/088.pdf) and summarized in section 3.2.2 of [Sampling from discrete Gaussians for lattice-based cryptography on a constrained device](https://link.springer.com/content/pdf/10.1007%2Fs00200-014-0218-3.pdf). It requires CDF tables of probabilities centered around single center to be kept, which are pre calculated in constructor. Peikert's inversion algorithm used in the methods GenerateInt, GenerateIntVector, GenerateVector and GenerateInteger. These methods are not prone to timing attacks but they are usable for single center, single deviation only. It should be also noted that the memory requirement grows with the standard deviation, therefore it is advised to use it with smaller deviations. 


## Samplers in DiscreteGaussianGeneratorGeneric

The class [DiscreteGaussianGeneratorGeneric](./discretegaussiangeneratorgeneric.h) was created for the experimental generic sampler developed by UCSD, and it contains the definitions for this new sampling method and base samplers required for this method.

* __Peikert's Inversion Method:__ Peikert's inversion method is the same with one defined in [DiscreteGaussianGenerator](./discretegaussiangenerator.h), and it's used in base samplers only. It is called from a BaseSampler object created with "PEIKERT" parameter by invoking GenerateInteger method.

* __Knuth-Yao Sampling:__ Knuth-Yao's method for sampling integers were summarized in section 5 of [Sampling from discrete Gaussians for lattice-based cryptography on a constrained device](https://link.springer.com/content/pdf/10.1007%2Fs00200-014-0218-3.pdf). It requires the calculation of probability matrix and then the Discrete Distribution Generating trees, which is handled in constructor. In order to use this method, it is required to call it from a BaseSampler object created with "KNUTH_YAO" parameter by invoking GenerateInteger method. Just like Peikert's inversion method, it is usable for single center, single deviation only while having a memory requirement proportional to standard deviation. It is also not vulnerable to timing attacks.

* __Generic Constant Time Sampling:__ The new generic sampler developed by UCSD was discussed in the paper [Gaussian Sampling over the Integers: Efficient, Generic, Constant-Time](https://eprint.iacr.org/2017/259). It combines a set of base samplers centered around various means and a single standard deviation to sample from arbitrary centers and standard deviations. The parameter selection is greatly discussed in header file, but in general the sampler requires a set of base samplers given as parameters and few precomputations, which are handled in construction phase. This method can be called by creating a DiscreteGaussianGeneratorGeneric object and invoking GenerateInteger method. It is not vulnerable to timing attacks.