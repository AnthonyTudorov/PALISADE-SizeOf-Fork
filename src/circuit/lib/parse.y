/**
 * @file parse.y -- yacc/bison grammar for circuits
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 *
 * This code defines the grammar for circuits. It requires Bison v3.0.4, and uses C++
 *
 */

%skeleton "lalr1.cc"
%require "3.0.4"
%defines
%define parser_class_name {parser}

%define api.token.constructor
%define api.value.type variant
%define parse.assert

%code requires
{
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include "circuitinput.h"
#include "circuitnode.h"

class pdriver;
}

%param { pdriver& driver }

%locations
%initial-action
{
  // Initialize the initial location.
  @$.begin.filename = @$.end.filename = &driver.file;
};

%define parse.trace
%define parse.error verbose

%code
{
#include "parsedriver.h"

#include "../lib/circuitnode.h"
}

/* C declarations */

%{

#define YYINITDEPTH 100000

%}

/* Bison declarations */

%define api.token.prefix {TOK_}
%token END 0
%token ENDL
%token INPUT CONST OUTPUTS INTEGER RATIONAL PLAINTEXT CIPHERTEXT RATIONALCIPHERTEXT
%token TYPEOF
%token LEFT_BRACK
%token RIGHT_BRACK
%token ADD
%token SUB
%token MUL
%token RSHIFT
%token DOTPROD
%token  <std::string>           	VERSION
%token  <std::string>           	COMMAND
%token  <int64_t>           			NUM
%token  <std::string>           	STR
%type   <std::vector<usint>>		numlist
%type   <std::vector<std::string>>	strlist
%type   <wire_type>          		type basic_type agg_type
%type	<CircuitNode*>				gate const input

/* Grammar rules */

%%

toplevel :      ENDLS version prog | version prog
                ;

prog:
        |       ENDLS line prog | line prog
                ;

line:           command
				{
				}
		| 		input
				{
					driver.graph.addNode($1, $1->GetId());
					driver.graph.addInput($1->GetId());
				}
		|		OUTPUTS	numlist ENDLS
				{
					for( int i : $2 ) {
						driver.graph.addOutput(i);
						driver.graph.getNodeById(i)->setAsOutput();
					}
				}
		| 		const
				{
					driver.graph.addNode($1, $1->GetId());
				}
		| 		gate
				{
					// put $1 in the CircuitGraph
					driver.graph.addNode($1, $1->GetId());
					
					// all of the inputs for $1 need to be marked as having $1 as their output
					for( auto input : $1->getInputs() ) {
						driver.graph.getNodeById(input)->addOutput($1->GetId());
					}
				}

version:        VERSION ENDLS
                {
                    //std::cout << "Version of this circuit: " << $1 << std::endl;
                }

command:        COMMAND strlist ENDLS
                ;


input:          NUM INPUT NUM TYPEOF type ENDLS
                {
                	//std::cout << "Adding input #" << $3 << " of type " << $5 << std::endl;
                	
                		$$ = new Input($1, $5);
                }

const:          NUM CONST TYPEOF INTEGER NUM ENDLS
                {
                    $$ = new ConstInt($1, $5);
                }
                | NUM CONST TYPEOF PLAINTEXT NUM ENDLS
                {
                    $$ = new ConstPtxt($1, $5);
                }
                
type:           basic_type 
				{
					$$ = $1;
				}
		|		agg_type
				{
					$$ = $1;
				}
				;

basic_type:		INTEGER
				{
					$$ = INT;
				}
				| RATIONAL
				{
					$$ = RAT;
				}
				| PLAINTEXT
				{
					$$ = PLAINTEXT;
				}
				| CIPHERTEXT
				{
					$$ = CIPHERTEXT;
				}
				| RATIONALCIPHERTEXT
				{
					$$ = RATIONALCIPHERTEXT;
				}
				
agg_type:		LEFT_BRACK INTEGER RIGHT_BRACK
                {
					$$ = VECTOR_INT;
				}
				| LEFT_BRACK RATIONAL RIGHT_BRACK
                {
					$$ = VECTOR_RAT;
                }
				| LEFT_BRACK LEFT_BRACK INTEGER RIGHT_BRACK RIGHT_BRACK
                {
					$$ = MATRIX_INT;
				}
				| LEFT_BRACK LEFT_BRACK RATIONAL RIGHT_BRACK RIGHT_BRACK
				{
					$$ = MATRIX_RAT;
                }

strlist:        /* empty */
                {
                     $$ = std::vector<std::string>();
                }
        |       strlist STR
                {
                    $1.push_back($2);
                    $$ = $1;
                }
        ;

numlist:       /* empty */
                {
                    $$ = std::vector<usint>();
                }
        |       numlist NUM
                {
                	$1.push_back($2);
                	$$ = $1;
                }
                ;

gate:			NUM ADD numlist ENDLS
                {
                    $$ = new EvalAddNode($1, $3);
                }
        |		NUM SUB numlist ENDLS
                {
                    $$ = new EvalSubNode($1, $3);
                }
        |		NUM MUL numlist ENDLS
                {
                    $$ = new EvalMultNode($1, $3);
                }
        |		NUM RSHIFT numlist ENDLS
				{
        				$$ = new EvalRShiftNode($1, $3);
				}
		|		NUM DOTPROD numlist ENDLS
				{
					$$ = new EvalInnerProdNode($1, $3);
				}

ENDLS:          ENDLS ENDL | ENDL
        ;

%%

void
yy::parser::error (const location_type& l,
                          const std::string& m)
{
  driver.error (l, m);
}
