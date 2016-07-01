// This is a main() file built to test math  operations
// D. Cousins

#include <iostream>
#include <fstream>
#include "../../lib/utils/inttypes.h"
#include "../../lib/math/backend.h"
#if 1
#include "../../lib/math/nbtheory.h"
#include "../../lib/math/distrgen.h"
#include "../../lib/lattice/elemparams.h"
#include "../../lib/lattice/ilparams.h"
#include "../../lib/lattice/ildcrtparams.h"
#include "../../lib/lattice/ilelement.h"
#include "../../lib/crypto/lwecrypt.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.cpp"
#include "../../lib/obfuscate/obfuscatelp.h"
#endif
#include "time.h"
#include <chrono>
#include "../../lib/utils/debug.h"
#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;


//define the main sections of the test
void test_BigBinaryInt(void); 	// test old version of big int
void test_BigBinaryVector(void); // test old version of big int vector
void test_bint(void);		 // test new version of bint
void test_bintvec(void);	 // test new vector version

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){

  //test_BigBinaryInt();
  //test_BigBinaryVector();
  test_bint();
  test_bintvec();

  return 0;
}


void test_BigBinaryInt () {
  cout<<"testing BigBinaryInt"<<endl;
  //Todo: add some timing tests

  return;
}

//helper function that bulds BigBinaryVector from a vector of strings
BigBinaryVector BBVfromStrvec( std::vector<std::string> &s) {
  BigBinaryVector a(s.size());
  for (usint i = 0; i< s.size(); i++){
    a.SetValAtIndex(i,s[i]);
  }
  return a;
}

//main BigBinaryVector test suite. tests math
void test_BigBinaryVector () {
  int nloop = 10000; //number of times to run each test for timing.

    bool dbg_flag = 1;		// if true then print dbg output


  TimeVar t1,t2,t3,t_total; // timers for TIC() TOC()
  double time1;		    // captures the time in usec.
  double time2;
  double time3;
  double timeTotal;		// overal time


  //there are two test cases, 1) small modulus 2)approx 48 bits.

  //note this fails BigBinaryInteger q1 = {"00000000000000163841"};
  BigBinaryInteger q1 ("00000000000000163841");
  BigBinaryInteger q2 ("00004057816419532801");
  // a: note this fails too!! BigBinaryVector a1 =
  //{"00000000000000127753", "00000000000000077706",
  //"00000000000000017133", "00000000000000022582",
  //"00000000000000112132", "00000000000000027625",
  //"00000000000000126773", "00000000000000008924",
  //"00000000000000125972", "00000000000000002551",
  //"00000000000000113837", "00000000000000112045",
  //"00000000000000100953", "00000000000000077352",
  //"00000000000000132013", "00000000000000057029", };

  // for each vector, define a, b inputs as vectors of strings


  std::vector<std::string> a1strvec = {
    "00000000000000127753", "00000000000000077706",
    "00000000000000017133", "00000000000000022582",
    "00000000000000112132", "00000000000000027625",
    "00000000000000126773", "00000000000000008924",
    "00000000000000125972", "00000000000000002551",
    "00000000000000113837", "00000000000000112045",
    "00000000000000100953", "00000000000000077352",
    "00000000000000132013", "00000000000000057029", };

  // this fails too!!! BigBinaryVector a1(a1string);
  // so I wrote this function
  BigBinaryVector a1 = BBVfromStrvec(a1strvec);
  a1.SetModulus(q1);

  std::vector<std::string> a2strvec = {
    "00000185225172798255",
    "00000098879665709163",
    "00003497410031351258",
    "00004012431933509255",
    "00001543020758028581",
    "00000135094568432141",
    "00003976954337141739",
    "00004030348521557120",
    "00000175940803531155",
    "00000435236277692967",
    "00003304652649070144",
    "00002032520019613814",
    "00000375749152798379",
    "00003933203511673255",
    "00002293434116159938",
    "00001201413067178193", };

  BigBinaryVector a2 = BBVfromStrvec(a2strvec);
  a2.SetModulus(q2);

  //b:
  std::vector<std::string> b1strvec = {
    "00000000000000066773",
    "00000000000000069572", "00000000000000142134",
    "00000000000000141115", "00000000000000123182",
    "00000000000000155822", "00000000000000128147",
    "00000000000000094818", "00000000000000135782",
    "00000000000000030844", "00000000000000088634",
    "00000000000000099407", "00000000000000053647",
    "00000000000000111689", "00000000000000028502",
    "00000000000000026401", };
  BigBinaryVector b1  = BBVfromStrvec(b1strvec);
  b1.SetModulus(q1);

  std::vector<std::string> b2strvec = {
    "00000698898215124963",
    "00000039832572186149", "00001835473200214782",
    "00001041547470449968", "00001076152419903743",
    "00000433588874877196", "00002336100673132075",
    "00002990190360138614", "00000754647536064726",
    "00000702097990733190", "00002102063768035483",
    "00000119786389165930", "00003976652902630043",
    "00003238750424196678", "00002978742255253796",
    "00002124827461185795", };

  BigBinaryVector b2 = BBVfromStrvec(b2strvec);
  b2.SetModulus(q2);

  //now test all mod functions Note BigBinaryVector implies modulus ALWAYS

  //load correct values of math functions of a and b
  //modadd:
  std::vector<std::string>  sum1strvec =
    {"00000000000000030685", "00000000000000147278",
     "00000000000000159267", "00000000000000163697",
     "00000000000000071473", "00000000000000019606",
     "00000000000000091079", "00000000000000103742",
     "00000000000000097913", "00000000000000033395",
     "00000000000000038630", "00000000000000047611",
     "00000000000000154600", "00000000000000025200",
     "00000000000000160515", "00000000000000083430", };
  BigBinaryVector sum1 = BBVfromStrvec(sum1strvec);
  sum1.SetModulus(q1);

  std::vector<std::string> sum2strvec =
    {"00000884123387923218", "00000138712237895312",
     "00001275066812033239", "00000996162984426422",
     "00002619173177932324", "00000568683443309337",
     "00002255238590741013", "00002962722462162933",
     "00000930588339595881", "00001137334268426157",
     "00001348899997572826", "00002152306408779744",
     "00000294585635895621", "00003114137516337132",
     "00001214359951880933", "00003326240528363988", };
  BigBinaryVector sum2 = BBVfromStrvec(sum2strvec);
  sum2.SetModulus(q2);

  // modsub:
  std::vector<std::string>  diff1strvec =
    {"00000000000000060980", "00000000000000008134",
     "00000000000000038840", "00000000000000045308",
     "00000000000000152791", "00000000000000035644",
     "00000000000000162467", "00000000000000077947",
     "00000000000000154031", "00000000000000135548",
     "00000000000000025203", "00000000000000012638",
     "00000000000000047306", "00000000000000129504",
     "00000000000000103511", "00000000000000030628", };
  BigBinaryVector diff1 = BBVfromStrvec(diff1strvec);
  diff1.SetModulus(q1);

  std::vector<std::string>  diff2strvec =
    {"00003544143377206093", "00000059047093523014",
     "00001661936831136476", "00002970884463059287",
     "00000466868338124838", "00003759322113087746",
     "00001640853664009664", "00001040158161418506",
     "00003479109686999230", "00003790954706492578",
     "00001202588881034661", "00001912733630447884",
     "00000456912669701137", "00000694453087476577",
     "00003372508280438943", "00003134402025525199", };
  BigBinaryVector diff2 = BBVfromStrvec(diff2strvec);
  diff2.SetModulus(q2);

  //modmul:

  std::vector<std::string> mul1strvec ={
    "00000000000000069404",
    "00000000000000064196", "00000000000000013039",
    "00000000000000115321", "00000000000000028519",
    "00000000000000151998", "00000000000000089117",
    "00000000000000080908", "00000000000000057386",
    "00000000000000039364", "00000000000000008355",
    "00000000000000146135", "00000000000000061336",
    "00000000000000031598", "00000000000000025961",
    "00000000000000087680", };

  BigBinaryVector mul1 = BBVfromStrvec(mul1strvec);
  mul1.SetModulus(q2);

  std::vector<std::string> mul2strvec ={
    "00000585473140075497",
    "00003637571624495703", "00001216097920193708",
    "00001363577444007558", "00000694070384788800",
    "00002378590980295187", "00000903406520872185",
    "00000559510929662332", "00000322863634303789",
    "00001685429502680940", "00001715852907773825",
    "00002521152917532260", "00000781959737898673",
    "00002334258943108700", "00002573793300043944",
    "00001273980645866111", };

  BigBinaryVector mul2 = BBVfromStrvec(mul2strvec);
  mul2.SetModulus(q2);

  BigBinaryVector c1,c2;	// result vectors

  // compute results for each function and compare.

  TIC(t_total);
  bool good = true;

  // test mod add for both cases
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModAdd(b1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModAdd(b1) computation time: " << "\t" << time1 << " us");
  if (c1 != sum1)
    cout << "bad add! "<<endl;

  // test mod sub for both cases
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModSub(b1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModSub(b1) computation time: " << "\t" << time1 << " us");
  if(c1 !=diff1)
    cout << "bad sub! "<<endl;

  //test mod multiply for both cases
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModMul(b1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModMul(b1) computation time: " << "\t" << time1 << " us");
  if (c1 != mul1)
    cout << "bad multiply! "<<endl;


  // test case two
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModAdd(b2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModAdd(b2) computation time: " << "\t" << time2 << " us");
  if (c2 != sum2)
    cout << "bad modadd! "<<endl;

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModSub(b2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModSub(b2) computation time: " << "\t" << time2 << " us");
  if (c2 != diff2)
    cout << "bad modsub! "<<endl;

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModMul(b2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModMul(b2) computation time: " << "\t" << time2 << " us");
  if (c2 != mul2)
    cout << "bad modmultiply! "<<endl;

  timeTotal = TOC(t_total);
  DEBUG("Total time: " << "\t" << timeTotal << " us");

  return;
}

void iftest (bool t, string v) {
  if (t) {
    cout <<"Fail ";
    cout<<v<<endl;
    //exit(-1);
  }else {
    cout <<"Succeed ";
      cout<<v<<endl;
  }

  return;
}

/////////////////////////////////////////////////////////////
void test_bint () {
	bool dbg_flag = 1;
  cout<<"testing bint"<<endl;


  { //crate a small bint

	  bint q1("00000000000000163841");
	   cout << "q1 contents"<<endl;
	   q1.PrintLimbsInDec();
	  //create a large bing
	    bint q2("00004057816419532801");
	    cout << "q2 contents"<<endl;
	    q2.PrintLimbsInDec();

  }

    //TEST(method_to_test_convert_to_double, ConvertToDouble)
    {
      bint x("104037585658683683");
      double xInDouble = 104037585658683683;

      DEBUG("x.tostring "<< x.ToString());
      DEBUG("xInDouble "<< xInDouble);
      DEBUG("x.ConvertToDouble "<< x.ConvertToDouble());
      iftest (xInDouble != x.ConvertToDouble()	," convert to double");
    }
  {
    bint calculatedResult;
    int expectedResult;
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      bint a("203450");
      bint b("2034");

      calculatedResult = a.Add(b);
      expectedResult = 205484;

      iftest (expectedResult!= calculatedResult.ConvertToUsint()
	,"testing plus_a_greater_than_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      bint a("2034");
      bint b("203450");


      calculatedResult = a.Add(b);
      expectedResult = 205484;

      iftest (expectedResult != calculatedResult.ConvertToUsint()
	,"testing plus_a_less_than_b");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
    // BYTE
    {
      bint a("768900");
      bint b("16523408");

      calculatedResult = a.Add(b);
      expectedResult = 17292308;

      iftest (expectedResult !=calculatedResult.ConvertToUsint(),
    		  "testing overflow_to_next_byte");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
    // BYTE
    {
      bint a("35");
      bint b("1015");

      calculatedResult = a.Add(b);
      expectedResult = 1050;

      iftest (expectedResult !=calculatedResult.ConvertToUsint(),
    		  "testing plus_no_overflow_to_next_byte");
    }

    /************************************************/
    /* TESTING OPERATOR += FOR ALL CONDITIONS       */
    /************************************************/

    // The operator "+=(Plus Equals)" does addition of two BigBinary
    // Integers a,b Calculates a+b, and stores result in a ConvertToUsint
    // converts BigBinaryInteger8y a to integer


    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      bint a("2034");
      bint b("203");

      a+=b;
      expectedResult = 2237;

      iftest (expectedResult != a.ConvertToUsint(),"testing plus_equals_a_greater_than_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      bint a("2034");
      bint b("203450");

      a+=b;
      expectedResult = 205484;

      iftest (expectedResult != a.ConvertToUsint(), "testing plus_equals_a_less_than_b");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
    // BYTE
    {
      bint a("768900");
      bint b("16523408");

      a+=b;
      expectedResult = 17292308;

      iftest (expectedResult !=a.ConvertToUsint(),"testing plus_equals_overflow_to_next_byte");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
    // BYTE
    {
      bint a("35");
      bint b("1015");

      a+=b;
      expectedResult = 1050;

      iftest (expectedResult !=a.ConvertToUsint(),"testing plus_equals_no_overflow_to_next_byte");
    }
    /************************************************/
    /* TESTING METHOD MINUS FOR ALL CONDITIONS      */
    /************************************************/

    // The method "Minus" does subtraction on two BigBinary Integers a,b
    // Returns a-b, which is stored in another BigBinary Integer
    // calculatedResult When a<b, the result is 0, since there is no
    // support for negative numbers as of now ConvertToUsint converts
    // bint calculatedResult to integer

    {
      // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

      bint a("20489");
      bint b("2034455");

      calculatedResult = a.Sub(b);
      expectedResult = 0;

      //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
      //ZERO
      iftest (expectedResult != calculatedResult.ConvertToUsint(), "testing minus_a_less_than_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {
      bint a("2048956567");
      bint b("2048956567");

      calculatedResult = a.Sub(b);
      expectedResult = 0;

      iftest (expectedResult != calculatedResult.ConvertToUsint(),"testing minus_a_equal_to_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {
      bint a("2048956567");
      bint b("2034455");

      calculatedResult = a.Sub(b);
      expectedResult = 2046922112;

      iftest (expectedResult !=calculatedResult.ConvertToUsint(), "testing minus_a_greater_than_b");
    }
    // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
    {
      bint a("196737");
      bint b("65406");

      calculatedResult = a.Sub(b);
      expectedResult = 131331;

      iftest (expectedResult !=calculatedResult.ConvertToUsint(),"testing minus_borrow_from_next_byte");
    }

    /************************************************/
    /* TESTING OPERATOR -= FOR ALL CONDITIONS       */
    /************************************************/

    // The operator "-=(Minus Equals)" does subtractionn of two BigBinary
    // Integers a,b Calculates a-b, and stores result in a Results to 0,
    // when a<b, since there is no concept of negative number as of now
    // ConvertToUsint converts bint a to integer
    {
      // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

      bint a("20489");
      bint b("2034455");

      a-=b;
      expectedResult = 0;

      //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
      //ZERO
      iftest (expectedResult != a.ConvertToUsint(), "testing minus_equals_a_less_than_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {
      bint a("2048956567");
      bint b("2048956567");

      a-=b;
      expectedResult = 0;

      iftest (expectedResult != a.ConvertToUsint(), "testing minus_equals_a_equal_to_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {

      bint a("2048956567");
      bint b("2034455");

      a-=b;
      expectedResult = 2046922112;

      iftest (expectedResult !=a.ConvertToUsint(), "testing minus_equals_a_greater_than_b");
    }
    // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
    {
      bint a("196737");
      bint b("65406");

      a-=b;
      expectedResult = 131331;

      iftest (expectedResult !=a.ConvertToUsint(), "testing minus_equals_borrow_from_next_byte");
    }

    /************************************************/
    /* TESTING METHOD TIMES FOR ALL CONDITIONS      */
    /************************************************/

    // The method "Times" does multiplication on two BigBinary Integers
    // a,b Returns a*b, which is stored in another BigBinary Integer
    // calculatedResult ConvertToUsint converts bint
    // calculatedResult to integer
    {
      //ask about the branching if (b.m_MSB==0 or 1)
      bint a("1967");
      bint b("654");

      calculatedResult = a.Mul(b);
      expectedResult = 1286418;

      iftest (expectedResult !=calculatedResult.ConvertToUsint(),"testing times_test");
    }
    /************************************************/
    /* TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS */
    /************************************************/

    // The method "Divided By" does division of BigBinary Integer a by
    // another BigBinary Integer b Returns a/b, which is stored in another
    // BigBinary Integer calculatedResult ConvertToUsint converts
    // bint calculatedResult to integer When b=0, throws
    // error, since division by Zero is not allowed When a<b, returns 0,
    // since decimal value is not returned


    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
    {
      bint a("2048");
      bint b("2034455");

      calculatedResult = a.DividedBy(b);
      expectedResult = 0;

      //RESULT SHOULD BE ZERO
      iftest (expectedResult != calculatedResult.ConvertToUsint(),"testing divided_by_a_less_than_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {

      bint a("2048956567");
      bint b("2048956567");

      calculatedResult = a.DividedBy(b);
      expectedResult = 1;

      iftest (expectedResult != calculatedResult.ConvertToUsint(),"testing divided_by_a_equals_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {
      bint a("2048956567");
      bint b("2034455");

      calculatedResult = a.DividedBy(b);
      expectedResult = 1007;

      iftest (expectedResult !=calculatedResult.ConvertToUsint(),"testing divided_by_a_greater_than_b");
    }
  }
  /************************************************/
  /* TESTING BASIC COMPARATOR METHODS AND OPERATORS */
  /**************************************************/

  /************************************************/
  /* TESTING METHOD COMPARE FOR ALL CONDITIONS    */
  /************************************************/

  // The method "Comapare" comapres two BigBinary Integers a,b
  // Returns:
  //    1, when a>b
  //    0, when a=b
  //   -1, when a<b
  //
  // Result is stored in signed integer, and then the result is
  // typecasted to int as  if  takes integer
  {
    sint c;
    int expectedResult;

    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER
    {
      bint a("112504");
      bint b("46968");

      c = a.Compare(b);
      expectedResult = 1;

      iftest (expectedResult !=(int)c,"testing compare_a_greater_than_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
    {
      bint a("12504");
      bint b("46968");

      c = a.Compare(b);
      expectedResult = -1;

      iftest (expectedResult !=(int)c	,"testing compare_a_less_than_b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
    {
      bint a("34512504");
      bint b("34512504");

      c = a.Compare(b);
      expectedResult = 0;

      iftest (expectedResult !=(int)c	,"testing compare_a_equals_b");
    }

  }
  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two BigBinary Integers
  // m,p Returns (m mod p), which is stored in another BigBinary Integer
  // calculatedResult ConvertToUsint converts bint r to
  // integer
  {
    bint calculatedResult;
    int expectedResult;
    // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
    {
      bint m("27");
      bint p("240");

      calculatedResult = m.Mod(p);
      expectedResult = 27;

      iftest (expectedResult !=calculatedResult.ConvertToUsint()	,"testing number_less_than_modulus");
    }
    // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
    {
      bint m("93409673");
      bint p("406");

      calculatedResult = m.Mod(p);
      expectedResult = 35;

      iftest (expectedResult !=calculatedResult.ConvertToUsint()	,"testing number_greater_than_modulus");
    }
    // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
    {
      bint m("32768");
      bint p("16");

      calculatedResult = m.Mod(p);
      expectedResult = 0;

      iftest (expectedResult !=calculatedResult.ConvertToUsint()	,"testing number_dividible_by_modulus");
    }

    // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
    {
      bint m("67108913");
      bint p("67108913");

      calculatedResult = m.Mod(p);
      expectedResult = 0;

      iftest (expectedResult !=calculatedResult.ConvertToUsint()	,"testing number_equal_to_modulus");
    }


    /************************************************/
    /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
    /************************************************/


    /* 	The method "Divided By" does division of BigBinary Integer m by another BigBinary Integer p
	Function takes b as argument and operates on a
  	Returns a/b, which is stored in another BigBinary Integer calculatedResult
	ConvertToUsint converts bint calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
    */



    // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

    /*TEST(UTBinInt_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

      bint a("9587");
      bint b("3591");
      bint c("177");

      bint calculatedResult = a.ModBarrett(b,c);
      int expectedResult = 205484;

      std::coutcout <<"\n"<<d.ConvertToUsint()<<"\n";	//for testing purpose

      // if (27,calculatedResult.ConvertToUsint());
      }
    */

    /*************************************************/
    /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
    /*************************************************/
    // The method "Mod Inverse" operates on BigBinary Integers m,p
    // Returns {(m)^(-1)}mod p
    //    which is multiplicative inverse of m with respect to p, and is
    //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
    //    of m and p is 1)
    // If m and p are not co-prime, the method throws an error
    // ConvertToUsint converts bint calculatedResult to integer


    // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
    {
    	bint m("5");
    	bint p("108");

    	try {
    		calculatedResult = m.ModInverse(p);
    	} catch (exception& e) {
    		cout <<"exception occurred "<< e.what() << endl;

    	}

    	expectedResult = 65;

    	iftest (expectedResult !=calculatedResult.ConvertToUsint()	,"testing number_less_than_modulus");
    }
    // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
    {
    	bint m("3017");
    	bint p("108");

    	try {
//    		calculatedResult = m.ModInverse(p);
    	  cout<< "this fails all the time"<<endl;
    	} catch (exception& e) {
    		cout <<"exception occurred "<< e.what() << endl;

    	}

    	expectedResult = 77;

    	iftest (expectedResult !=calculatedResult.ConvertToUsint()	,"testing number_greater_than_modulus");
    }


    /************************************************/
    /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
    /************************************************/
    // The method "Mod Add" operates on BigBinary Integers m,n,q
    //   Returns:
    //     (m+n)mod q
    //      = {(m mod q) + (n mod q)}mod q
    //   ConvertToUsint converts bint calculatedResult to integer




    // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
    {
      bint m("58059595");
      bint n("3768");
      bint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 2871;

      iftest (expectedResult !=calculatedResult.ConvertToUsint()	,"testing first_number_greater_than_modulus");
    }
    // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
    {
      bint m("595");
      bint n("376988");
      bint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 3419;

      iftest (expectedResult !=calculatedResult.ConvertToUsint(),"testing second_number_greater_than_modulus");
    }
    // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
    {
      bint m("595");
      bint n("376");
      bint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 971;
      iftest (expectedResult != calculatedResult.ConvertToUsint()	,"testing both_numbers_less_than_modulus");
    }
    // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
    {

      bint m("59509095449");
      bint n("37654969960");
      bint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 2861;

      iftest (expectedResult != calculatedResult.ConvertToUsint()	,"testing both_numbers_greater_than_modulus");
    }

    /************************************************/
    /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
    /************************************************/

    // The method "Mod Sub" operates on BigBinary Integers m,n,q
    //   Returns:
    //    (m-n)mod q
    //    = {(m mod q) - (n mod q)}mod q	when m>n
    //    = 0 when m=n
    //    = {(m mod q)+q-(n mod q)}mod q when m<n

    //   ConvertToUsint converts bint calculatedResult to
    //   integer

    //MEMORY ALLOCATION ERROR IN MODSUB METHOD (due to copying value to null pointer)


    // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
    {
      bint m("595");
      bint n("399");
      bint q("406");

      //std::cout << "Before : " << std::endl;

      calculatedResult = m.ModSub(n,q);
      expectedResult = 196;

      iftest (expectedResult != calculatedResult.ConvertToUsint()	,"testing first_number_greater_than_modulus");
    }
    // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
    {
      bint m("39960");
      bint n("595090959");
      bint q("406756");

      calculatedResult = m.ModSub(n,q);
      expectedResult = 33029;

      //[{(a mod c)+ c} - (b mod c)] since a < b
      iftest (expectedResult !=calculatedResult.ConvertToUsint()
	,"testing first_number_less_than_modulus");
    }
    // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
    {
      bint m("595090959");
      bint n("595090959");
      bint q("406756");

      calculatedResult = m.ModSub(n,q);
      expectedResult = 0;

      iftest (expectedResult != calculatedResult.ConvertToUsint()
	,"testing first_number_equals_second_number");
    }

    /************************************************/
    /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
    /************************************************/

    // The method "Mod Mul" operates on BigBinary Integers m,n,q
    //   Returns:  (m*n)mod q
    //              = {(m mod q)*(n mod q)}
    // ConvertToUsint converts bint calculatedResult to integer

    {
      bint m("39960");
      bint n("7959");
      bint q("406756");

      bint calculatedResult = m.ModMul(n,q);
      int expectedResult = 365204;

      iftest (expectedResult != calculatedResult.ConvertToUsint()
	,"testing mod_mul_test");
    }

    /************************************************/
    /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
    /************************************************/

    // The method "Mod Exp" operates on BigBinary Integers m,n,q
    // Returns:  (m^n)mod q
    //   = {(m mod q)^(n mod q)}mod q
    // ConvertToUsint converts bint calculatedResult to integer

    {
      bint m("39960");
      bint n("9");
      bint q("406756");

      bint calculatedResult = m.ModExp(n,q);
      int expectedResult = 96776;

      iftest (expectedResult != calculatedResult.ConvertToUsint()
	,"testing mod_exp_test");
    }

    /****************************/
    /* TESTING SHIFT OPERATORS  */
    /****************************/

    /*******************************************************/
    /* TESTING OPERATOR LEFT SHIFT (<<) FOR ALL CONDITIONS */
    /*******************************************************/

    // The operator 'Left Shift' operates on BigBinary Integer a, and it
    // is shifted by a number

    // Returns: a<<(num), and the result is stored in BigBinaryInterger
    // calculatedResult 'a' is left shifted by 'num' number of bits, and
    // filled up by 0s from right which is equivalent to a * (2^num)
    //
    //        example:
    //            4<<3 => (100)<<3 => (100000) => 32
    //           this is equivalent to: 4* (2^3) => 4*8 =32
    //ConvertToUsint converts bint calculatedResult to integer

    // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39960");
      usshort shift = 3;

      bint calculatedResult = a<<(shift);
      int expectedResult = 319680;

      iftest (expectedResult != calculatedResult.ConvertToUsint()
	,"testing shift_less_than_max_shift");
    }
    // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39960");
      usshort shift = 6;

      bint calculatedResult = a<<(shift);
      int expectedResult = 2557440;

      iftest (expectedResult != calculatedResult.ConvertToUsint(),"testing shift_greater_than_max_shift");
    }


    /************************************************/
    /* TESTING OPERATOR LEFT SHIFT EQUALS (<<=) FOR ALL CONDITIONS -*/
    /************************************************/

    // The operator 'Left Shift Equals' operates on BigBinary Integer a,
    // and it is shifted by a number
    // Returns:
    // a<<(num), and the result is stored in 'a'
    // 'a' is left shifted by 'num' number of bits, and filled up by 0s
    // from right which is equivalent to a * (2^num)
    // example :4<<3 => (100)<<3 => (100000) => 32
    // this is equivalent to: 4* (2^3) => 4*8 =32
    // ConvertToInt converts bint a to integer




    // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39960");
      usshort num = 3;

      a<<=(num);
      int expectedResult = 319680;

      iftest (expectedResult != a.ConvertToUsint()
	,"testing shift_less_than_max_shift");
    }
    // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39960");
      usshort num = 6;

      a<<=(num);
      int expectedResult = 2557440;

      iftest (expectedResult != a.ConvertToUsint()
	,"testing shift_greater_than_max_shift");
    }


    /********************************************************/
    /* TESTING OPERATOR RIGHT SHIFT (>>) FOR ALL CONDITIONS */
    /********************************************************/
    // The operator 'Right Shift' operates on BigBinary Integer a, and it
    // is shifted by a number

    // Returns: a>>(num), and the result is stored in BigBinary Integer
    // calculated. Result 'a' is right shifted by 'num' number of bits,
    // and filled up by 0s from left which is equivalent to a / (2^num)

    //  ex:4>>3 => (100000)>>3 => (000100) => 4

    // this is equivalent to: 32*(2^3) => 32/8 = 4
    // ConvertToUsint converts bint calculatedResult to integer


    // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39965675");
      usshort shift = 3;

      bint calculatedResult = a>>(shift);
      int expectedResult = 4995709;

      iftest (expectedResult != calculatedResult.ConvertToUsint()
	,"testing shift_less_than_max_shift");
    }
    // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39965675");
      usshort shift = 6;

      bint calculatedResult = a>>(shift);
      int expectedResult = 624463;

      iftest (expectedResult != calculatedResult.ConvertToUsint()
	,"testing shift_greater_than_max_shift");
    }


    /***************************************************************/
    /* TESTING OPERATOR RIGHT SHIFT EQUALS(>>=) FOR ALL CONDITIONS */
    /***************************************************************/

    // The operator 'Right Shift Equals' operates on BigBinary Integer a,
    // and it is shifted by a number

    // Returns: a>>=(num), and the result is stored in a 'a' is right
    // shifted by 'num' number of bits, and filled up by 0s from left
    // which is equivalent to a / (2^num)

    //   ex:4>>3 => (100000)>>3 => (000100) => 4

    //   this is equivalent to: 32*(2^3) => 32/8 = 4
    //   ConvertToUsint converts bint calculatedResult to integer


    // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39965675");
      usshort shift = 3;

      a>>=(shift);
      int expectedResult = 4995709;

      iftest (expectedResult != a.ConvertToUsint(), "testing shift_less_than_max_shift");
    }
    // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
      bint a("39965675");
      usshort shift = 6;

      a>>=(shift);
      int expectedResult = 624463;

      iftest (expectedResult != a.ConvertToUsint()
	,"testing shift_greater_than_max_shift");
    }


    /****************************************/
    /* TESTING METHOD  BinaryToBigBinaryInt */
    /****************************************/

    {
    std:string binaryString = "1011101101110001111010111011000000011";
      bint b =
	lbcrypto::bint::BinaryStringToBint(binaryString);

      bint expectedResult("100633769475");
      iftest (expectedResult != b	,"testing BinaryToBigBinaryInt");
    }

    /****************************************/
    /* TESTING METHOD  EXP                  */
    /****************************************/
    {
      bint x("56");
      bint result = x.Exp(10);

      bint expectedResult("303305489096114176");
      iftest (expectedResult != result 	,"testing exp");
    }


  }


  return;
}

void test_bintvec() {

  int nloop = 10000; //number of times to run each test for timing.

  bool dbg_flag = 1;		// if true then print dbg output

  TimeVar t1,t2,t3,t_total; // timers for TIC() TOC()
  double time1;		    // captures the time in usec.
  double time2;
  double time3;
  double timeTotal;		// overal time

  cout<<"testing bintvec"<<endl;
  //there are two test cases, 1) small modulus 2)approx 48 bits.
  // q1 modulus 1:
  bint q1("00000000000000163841");
  cout << "q1 contents"<<endl;
  q1.PrintLimbsInDec();
  // a1:
  std::vector<std::string>  a1sv = {"00000000000000127753", "00000000000000077706", "00000000000000017133", "00000000000000022582", "00000000000000112132", "00000000000000027625", "00000000000000126773", "00000000000000008924", "00000000000000125972", "00000000000000002551", "00000000000000113837", "00000000000000112045", "00000000000000100953", "00000000000000077352", "00000000000000132013", "00000000000000057029", };
  bintvec a1(a1sv);

  // b1:
  std::vector<std::string>  b1sv = {"00000000000000066773", "00000000000000069572", "00000000000000142134", "00000000000000141115", "00000000000000123182", "00000000000000155822", "00000000000000128147", "00000000000000094818", "00000000000000135782", "00000000000000030844", "00000000000000088634", "00000000000000099407", "00000000000000053647", "00000000000000111689", "00000000000000028502", "00000000000000026401", };
  bintvec b1(b1sv);

  // add1:
  std::vector<std::string>  add1sv = {"00000000000000194526", "00000000000000147278", "00000000000000159267", "00000000000000163697", "00000000000000235314", "00000000000000183447", "00000000000000254920", "00000000000000103742", "00000000000000261754", "00000000000000033395", "00000000000000202471", "00000000000000211452", "00000000000000154600", "00000000000000189041", "00000000000000160515", "00000000000000083430", };
  bintvec add1(add1sv);

  // sub1:
#if 0 //set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub1sv = {"00000000000000060980", "00000000000000008134", "18446744073709426615", "18446744073709433083", "18446744073709540566", "18446744073709423419", "18446744073709550242", "18446744073709465722", "18446744073709541806", "18446744073709523323", "00000000000000025203", "00000000000000012638", "00000000000000047306", "18446744073709517279", "00000000000000103511", "00000000000000030628", };
#else
  std::vector<std::string> sub1sv = {"00000000000000060980", "00000000000000008134", "00000000000000000000", "00000000000000000000", "00000000000000000000", "00000000000000000000", "00000000000000000000", "00000000000000000000", "00000000000000000000", "00000000000000000000", "00000000000000025203", "00000000000000012638", "00000000000000047306", "00000000000000000000", "00000000000000103511", "00000000000000030628", };
#endif
  bintvec sub1(sub1sv);

  // mul1:
  std::vector<std::string>  mul1sv = {"000000000000000000000000000008530451069", "000000000000000000000000000005406161832", "000000000000000000000000000002435181822", "000000000000000000000000000003186658930", "000000000000000000000000000013812644024", "000000000000000000000000000004304582750", "000000000000000000000000000016245579631", "000000000000000000000000000000846155832", "000000000000000000000000000017104730104", "000000000000000000000000000000078683044", "000000000000000000000000000010089828658", "000000000000000000000000000011138057315", "000000000000000000000000000005415825591", "000000000000000000000000000008639367528", "000000000000000000000000000003762634526", "000000000000000000000000000001505622629", };
  bintvec mul1(mul1sv);

  // modadd1:
  std::vector<std::string>  modadd1sv = {"00000000000000030685", "00000000000000147278", "00000000000000159267", "00000000000000163697", "00000000000000071473", "00000000000000019606", "00000000000000091079", "00000000000000103742", "00000000000000097913", "00000000000000033395", "00000000000000038630", "00000000000000047611", "00000000000000154600", "00000000000000025200", "00000000000000160515", "00000000000000083430", };
  bintvec modadd1(modadd1sv);

  // modsub1:
  std::vector<std::string>  modsub1sv = {"00000000000000060980", "00000000000000008134", "00000000000000038840", "00000000000000045308", "00000000000000152791", "00000000000000035644", "00000000000000162467", "00000000000000077947", "00000000000000154031", "00000000000000135548", "00000000000000025203", "00000000000000012638", "00000000000000047306", "00000000000000129504", "00000000000000103511", "00000000000000030628", };
  bintvec modsub1(modsub1sv);

  // modmul1:
  std::vector<std::string>  modmul1sv = {"00000000000000069404", "00000000000000064196", "00000000000000013039", "00000000000000115321", "00000000000000028519", "00000000000000151998", "00000000000000089117", "00000000000000080908", "00000000000000057386", "00000000000000039364", "00000000000000008355", "00000000000000146135", "00000000000000061336", "00000000000000031598", "00000000000000025961", "00000000000000087680", };
  bintvec modmul1(modmul1sv);

  bintvec c1;
  // test math for case 1
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1 + b1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1 + b1) computation time: " << "\t" << time1 << " us");
  if (c1 != add1)
    cout << "bad add" <<endl;


  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1 - b1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1 - b1 computation time: " << "\t" << time1 << " us");
  if (c1 != sub1) {
    cout << "bad sub" <<endl;

    //todo:  note the following is for debugging... remove when done
    for (usint i= 0; i < c1.GetLength(); ++i){  //todo change to size()
      // if (c1.GetValAtIndex(i) != sub1.GetValAtIndex(i)) {  //todo: add [] indexing to class
      cout << "i: "<< i << endl;

      cout << "c1   :" << c1.GetValAtIndex(i);
      cout << endl;
      cout << "state " << c1.GetValAtIndex(i).m_state << endl;;
      cout << "msb: " << c1.GetValAtIndex(i).m_MSB << endl;;
      cout << endl;
      cout << "sub1 :" << sub1.GetValAtIndex(i);
      cout << endl;
      cout << "state " << sub1.GetValAtIndex(i).m_state << endl;
      cout << "msb: " << sub1.GetValAtIndex(i).m_MSB << endl;
      cout << endl;
      // }
    }
  }

  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1 * b1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1 * b1 computation time: " << "\t" << time1 << " us");
  if (c1 != mul1) {
    cout << "bad mul" <<endl;
    for (usint i= 0; i < c1.GetLength(); ++i){  //todo change to size()
      if (c1.GetValAtIndex(i) != mul1.GetValAtIndex(i)) {  //todo: add [] indexing to class
	cout << "i: "<< i << endl;

	cout << "c1   :" << c1.GetValAtIndex(i);
	cout << endl;
	cout << "state " << c1.GetValAtIndex(i).m_state << endl;;
	cout << "msb: " << c1.GetValAtIndex(i).m_MSB << endl;;
	cout << endl;
	cout << "mul1 :" << mul1.GetValAtIndex(i);
	cout << endl;
	cout << "state " << mul1.GetValAtIndex(i).m_state << endl;
	cout << "msb: " << mul1.GetValAtIndex(i).m_MSB << endl;
	cout << endl;
      }
    }
  }

  //now Mod operations
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModAdd(b1,q1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModAdd(b1,q1) computation time: " << "\t" << time1 << " us");
  if (c1 != modadd1)
    cout << "bad modadd" <<endl;

  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModSub(b1,q1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModSub(b1,q1) computation time: " << "\t" << time1 << " us");

  if (c1 != modsub1) {
    cout << "bad modsub" <<endl;

    //todo:  note the following is for debugging... remove when done
    for (usint i= 0; i < c1.GetLength(); ++i){  //todo change to size()
      // if (c1.GetValAtIndex(i) != sub1.GetValAtIndex(i)) {  //todo: add [] indexing to class
      cout << "i: "<< i << endl;

      cout << "c1   :" << c1.GetValAtIndex(i);
      cout << endl;
      cout << "state " << c1.GetValAtIndex(i).m_state << endl;;
      cout << "msb: " << c1.GetValAtIndex(i).m_MSB << endl;;
      cout << endl;
      cout << "msub1:" << modsub1.GetValAtIndex(i);
      cout << endl;
      cout << "state " << modsub1.GetValAtIndex(i).m_state << endl;
      cout << "msb: " << modsub1.GetValAtIndex(i).m_MSB << endl;
      cout << endl;
      // }
    }
  }

  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModMul(b1,q1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModMul(b1,q1)  computation time: " << "\t" << time1 << " us");
  if (c1 != modmul1) {
    cout << "bad mul" <<endl;
    for (usint i= 0; i < c1.GetLength(); ++i){  //todo change to size()
      if (c1.GetValAtIndex(i) != modmul1.GetValAtIndex(i)) {  //todo: add [] indexing to class
	cout << "i: "<< i << endl;
	cout << "c1   :" << c1.GetValAtIndex(i);
	cout << endl;
	cout << "state " << c1.GetValAtIndex(i).m_state << endl;;
	cout << "msb: " << c1.GetValAtIndex(i).m_MSB << endl;;
	cout << endl;
	cout << "mmul1:" << modmul1.GetValAtIndex(i);
	cout << endl;
	cout << "state " << modmul1.GetValAtIndex(i).m_state << endl;
	cout << "msb: " << modmul1.GetValAtIndex(i).m_MSB << endl;
	cout << endl;
      }
    }
  }

  // q2:

  bint q2("00004057816419532801");
  cout << "q2 contents"<<endl;
  q2.PrintLimbsInDec();

  // a2:
  std::vector<std::string>  a2sv = {"00000185225172798255", "00000098879665709163", "00003497410031351258", "00004012431933509255", "00001543020758028581", "00000135094568432141", "00003976954337141739", "00004030348521557120", "00000175940803531155", "00000435236277692967", "00003304652649070144", "00002032520019613814", "00000375749152798379", "00003933203511673255", "00002293434116159938", "00001201413067178193", };
  bintvec a2(a2sv);

  // b2:
  std::vector<std::string>  b2sv = {"00000698898215124963", "00000039832572186149", "00001835473200214782", "00001041547470449968", "00001076152419903743", "00000433588874877196", "00002336100673132075", "00002990190360138614", "00000754647536064726", "00000702097990733190", "00002102063768035483", "00000119786389165930", "00003976652902630043", "00003238750424196678", "00002978742255253796", "00002124827461185795", };

  bintvec b2(b2sv);
  // add2:
  std::vector<std::string>  add2sv = {"00000884123387923218", "00000138712237895312", "00005332883231566040", "00005053979403959223", "00002619173177932324", "00000568683443309337", "00006313055010273814", "00007020538881695734", "00000930588339595881", "00001137334268426157", "00005406716417105627", "00002152306408779744", "00004352402055428422", "00007171953935869933", "00005272176371413734", "00003326240528363988", };

  bintvec add2(add2sv);
  // sub2:
#if 0 //set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub2sv = {"18446230400667224908", "00000059047093523014", "00001661936831136476", "00002970884463059287", "00000466868338124838", "18446445579403106561", "00001640853664009664", "00001040158161418506", "18446165366977018045", "18446477211996511393", "00001202588881034661", "00001912733630447884", "18443143169959719952", "00000694453087476577", "18446058765570457758", "18445820659315544014", };
#else
  std::vector<std::string>  sub2sv = {"00000000000000000000", "00000059047093523014", "00001661936831136476", "00002970884463059287", "00000466868338124838", "00000000000000000000", "00001640853664009664", "00001040158161418506", "00000000000000000000", "00000000000000000000", "00001202588881034661", "00001912733630447884", "00000000000000000000", "00000694453087476577", "00000000000000000000", "00000000000000000000", };
#endif
  bintvec sub2(sub2sv);

  // mul2:
  std::vector<std::string>  mul2sv = {"000000000129453542664913267883213339565", "000000000003938631422102517149330983287", "000000006419402382707574566639285895756", "000000004179138330699238739092142453840", "000000001660525522714165323210462878683", "000000000058575501928512376649634356636", "000000009290565704012341618368342178425", "000000012051509297159015143330318631680", "000000000132773293878034164433437538530", "000000000305578516062424854278036474730", "000000006946590599552827582889547919552", "000000000243468234057004000432166157020", "000000001494223959136453394722407100297", "000000012738664541883618180978992446890", "000000006831549111446250063725117624648", "000000002552795477367678807574345368435", };
  bintvec mul2(mul2sv);

  // modadd2:
  std::vector<std::string>  modadd2sv = {"00000884123387923218", "00000138712237895312", "00001275066812033239", "00000996162984426422", "00002619173177932324", "00000568683443309337", "00002255238590741013", "00002962722462162933", "00000930588339595881", "00001137334268426157", "00001348899997572826", "00002152306408779744", "00000294585635895621", "00003114137516337132", "00001214359951880933", "00003326240528363988", };
  bintvec modadd2(modadd2sv);

  // modsub2:
  std::vector<std::string>  modsub2sv = {"00003544143377206093", "00000059047093523014", "00001661936831136476", "00002970884463059287", "00000466868338124838", "00003759322113087746", "00001640853664009664", "00001040158161418506", "00003479109686999230", "00003790954706492578", "00001202588881034661", "00001912733630447884", "00000456912669701137", "00000694453087476577", "00003372508280438943", "00003134402025525199", };
  bintvec modsub2(modsub2sv);

  // modmul2:
  std::vector<std::string>  modmul2sv = {"00000585473140075497", "00003637571624495703", "00001216097920193708", "00001363577444007558", "00000694070384788800", "00002378590980295187", "00000903406520872185", "00000559510929662332", "00000322863634303789", "00001685429502680940", "00001715852907773825", "00002521152917532260", "00000781959737898673", "00002334258943108700", "00002573793300043944", "00001273980645866111", };
  bintvec modmul2(modmul2sv);

  bintvec c2;
  // test math for case 2
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2 + b2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2 + b2) computation time: " << "\t" << time2 << " us");

  if (c2 != add2)
    cout << "bad add" <<endl;


  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2 - b2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2 - b2 computation time: " << "\t" << time2 << " us");

  if (c2 != sub2) {
    cout << "bad sub" <<endl;

    //todo:  note the following is for debugging... remove when done
    for (usint i= 0; i < c2.GetLength(); ++i){  //todo change to size()
      // if (c2.GetValAtIndex(i) != sub2.GetValAtIndex(i)) {  //todo: add [] indexing to class
      cout << "i: "<< i << endl;

      cout << "c2   :" << c2.GetValAtIndex(i);
      cout << endl;
      cout << "state " << c2.GetValAtIndex(i).m_state << endl;;
      cout << "msb: " << c2.GetValAtIndex(i).m_MSB << endl;;
      cout << endl;
      cout << "sub2 :" << sub2.GetValAtIndex(i);
      cout << endl;
      cout << "state " << sub2.GetValAtIndex(i).m_state << endl;
      cout << "msb: " << sub2.GetValAtIndex(i).m_MSB << endl;
      cout << endl;
      // }
    }
  }

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2 * b2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2 * b2 computation time: " << "\t" << time2 << " us");
  if (c2 != mul2) {
    cout << "bad mul" <<endl;
    for (usint i= 0; i < c2.GetLength(); ++i){  //todo change to size()
      if (c2.GetValAtIndex(i) != mul2.GetValAtIndex(i)) {  //todo: add [] indexing to class
	cout << "i: "<< i << endl;

	cout << "c2   :" << c2.GetValAtIndex(i);
	cout << endl;
	cout << "state " << c2.GetValAtIndex(i).m_state << endl;;
	cout << "msb: " << c2.GetValAtIndex(i).m_MSB << endl;;
	cout << endl;
	cout << "mul2 :" << mul2.GetValAtIndex(i);
	cout << endl;
	cout << "state " << mul2.GetValAtIndex(i).m_state << endl;
	cout << "msb: " << mul2.GetValAtIndex(i).m_MSB << endl;
	cout << endl;
      }
    }
  }
  //now Mod operations
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModAdd(b2,q2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModAdd(b2,q2) computation time: " << "\t" << time2 << " us");
  if (c2 != modadd2)
    cout << "bad modadd" <<endl;

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModSub(b2,q2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModSub(b2,q2) computation time: " << "\t" << time2 << " us");
  if (c2 != modsub2) {
    cout << "bad modsub" <<endl;
    //todo:  note the following is for debugging... remove when done
    for (usint i= 0; i < c2.GetLength(); ++i){  //todo change to size()
      // if (c2.GetValAtIndex(i) != sub2.GetValAtIndex(i)) {  //todo: add [] indexing to class
      cout << "i: "<< i << endl;
      cout << "c2   :" << c2.GetValAtIndex(i);
      cout << endl;
      cout << "state " << c2.GetValAtIndex(i).m_state << endl;;
      cout << "msb: " << c2.GetValAtIndex(i).m_MSB << endl;;
      cout << endl;
      cout << "msub2:" << modsub2.GetValAtIndex(i);
      cout << endl;
      cout << "state " << modsub2.GetValAtIndex(i).m_state << endl;
      cout << "msb: " << modsub2.GetValAtIndex(i).m_MSB << endl;
      cout << endl;
      // }
    }
  }

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModMul(b2,q2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModMul(b2,q2)  computation time: " << "\t" << time2 << " us");
  if (c2 != modmul2) {
    cout << "bad mul" <<endl;
    for (usint i= 0; i < c2.GetLength(); ++i){  //todo change to size()
      if (c2.GetValAtIndex(i) != modmul2.GetValAtIndex(i)) {  //todo: add [] indexing to class
	cout << "i: "<< i << endl;

	cout << "c2   :" << c2.GetValAtIndex(i);
	cout << endl;
	cout << "state " << c2.GetValAtIndex(i).m_state << endl;;
	cout << "msb: " << c2.GetValAtIndex(i).m_MSB << endl;;
	cout << endl;
	cout << "mmul2:" << modmul2.GetValAtIndex(i);
	cout << endl;
	cout << "state " << modmul2.GetValAtIndex(i).m_state << endl;
	cout << "msb: " << modmul2.GetValAtIndex(i).m_MSB << endl;
	cout << endl;
      }
    }
  }

  return ;
}
