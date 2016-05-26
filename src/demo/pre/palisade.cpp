//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	6/17/2015 4:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Jerry Ryan, gwryan@njit.edu
Description:
	This code provides a command line to exercise the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.

	We configured parameters (namely the ring dimension and ciphertext modulus)
	to provide a level of security roughly equivalent to a root hermite factor of 1.007
	which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor
	and may be closer to AES-256.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#include <string>
#include <iostream>
using namespace std;

void
usage(const string& msg = "")
{
	if( msg.length() > 0 )
		cerr << msg << endl;

	cerr << "Usage is: palisade {cmd} {args}, where:" << endl;
	cerr << "\tmakekey [optional key parms] keyname" << endl;
	cerr << "\t\tcreate a new keypair and save in keyfilePUB.txt and keyfilePRI.txt" << endl;

	cerr << "\tmakerekey [optional key parms] pubkey_file secretkey_file rekey_file" << endl;
	cerr << "\t\tcreate a re-encryption key from the contents of pubkey_file and secretkey_file, save in rekey_file" << endl;

	cerr << "\tencrypt [optional parms] plaintext_file key_file ciphertext_file" << endl;
	cerr << "\t\tencrypt the contents of plaintext_file using the contents of key_file, save results in ciphertext_file" << endl;

	cerr << "\treencrypt [optional parms] encrypted_file key_file reencrypted_file" << endl;
	cerr << "\t\treencrypt the contents of encrypted_file using the contents of key_file, save results in reencrypted_file" << endl;

	cerr << "\tdecrypt [optional parms] ciphertext_file key_file cleartext_file" << endl;
	cerr << "\t\tdecrypt the contents of ciphertext_file using the contents of key_file, save results in cleartext_file" << endl;
}

int
main( int argc, char *argv[] )
{
	if( argc < 2 ) {
		usage();
		return 1;
	}

	return 0;
}
