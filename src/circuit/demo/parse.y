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
%token INPUT CONST OUTPUTS
%token TYPEOF
%token LEFT_BRACK
%token RIGHT_BRACK
%token ADD
%token SUB
%token MUL
%token  <std::string>           	VERSION
%token  <std::string>           	COMMAND
%token  <int>           			NUM
%token  <std::string>           	STR
%type   <std::vector<int>>			numlist
%type   <std::vector<std::string>>	strlist
%type   <wire_type>          		type basic_type agg_type
%type	<CircuitNode*>				gate
%type	<CircuitNode*>				input

/*%printer { yyoutput << $$; } <*>; */

/* Grammar rules */

%%

toplevel :      version prog
                ;

prog:
        |       line prog
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
					
				}
		| 		gate
				{
					// put $1 in the CircuitGraph
					driver.graph.addNode($1, $1->GetId());
					//driver.graph.addInput($1->GetId());
				}

version:        VERSION ENDLS
                {
                    std::cout << "Version of this circuit: " << $1 << std::endl;
                }

command:        COMMAND strlist ENDLS
                ;


input:          NUM INPUT NUM TYPEOF type ENDLS
                {
                	std::cout << "Adding input #" << $3 << " of type " << $5 << std::endl;
                	
                	$$ = new Input($1, $5);
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

basic_type:		STR
                {
                    if ($1 == "Integer") {
                      $$ = INT;
                    } else if ($1 == "Rational") {
                      $$ = RATIONAL;
                    } else {
                      syntax_error(@1, string("Unknown type ") + $1);
                      YYERROR;
                    }
                }
agg_type:		LEFT_BRACK basic_type RIGHT_BRACK
                {
                    if ($2 == INT) {
                      $$ = VECTOR_INT;
                    } else if ($2 == RATIONAL) {
                      $$ = VECTOR_RAT;
                    }
                }
    |           LEFT_BRACK LEFT_BRACK basic_type RIGHT_BRACK RIGHT_BRACK
                {
                    if ($3 == INT) {
                      $$ = MATRIX_INT;
                    } else if ($3 == RATIONAL) {
                      $$ = MATRIX_RAT;
                    }
                }
    ;


const:          NUM CONST NUM ENDLS
                {
                    std::cout << "Adding the constant " << $3 << std::endl;
                }
        ;

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
                    $$ = std::vector<int>();
                }
        |       numlist NUM
                {
                	$1.push_back($2);
                	$$ = $1;
                }
                ;

gate:           NUM ADD numlist ENDLS
                {
                    $$ = new EvalAddNode($1, $3);
                }
        |       NUM SUB numlist ENDLS
                {
                    $$ = new EvalSubNode($1, $3);
                }
        |       NUM MUL numlist ENDLS
                {
                    $$ = new EvalMultNode($1, $3);
                }
                ;

ENDLS:          ENDLS ENDL | ENDL
        ;

%%

void
yy::parser::error (const location_type& l,
                          const std::string& m)
{
  driver.error (l, m);
}
