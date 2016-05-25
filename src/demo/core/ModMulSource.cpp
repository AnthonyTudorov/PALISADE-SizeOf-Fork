// This is a main() file built to test modulo multiply operations
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




//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  int array_size = 1000;
  float foo[array_size];

  bool dbg_flag = 1;

  TimeVar t1,t2,t3,t_total; //for TIC TOC
  double time1;
  double time2;
  double time3;
  double timeTotal;

    //note this fails BigBinaryInteger q1 = {"00000000000000163841"};
  BigBinaryInteger q1 ("00000000000000163841");
  BigBinaryInteger q2 ("00004057816419532801");
  // a:
  //note this fails too!! BigBinaryVector a1 = {"00000000000000127753", "00000000000000077706", "00000000000000017133", "00000000000000022582", "00000000000000112132", "00000000000000027625", "00000000000000126773", "00000000000000008924", "00000000000000125972", "00000000000000002551", "00000000000000113837", "00000000000000112045", "00000000000000100953", "00000000000000077352", "00000000000000132013", "00000000000000057029", };
  std::vector<std::string> a1strvec = {"00000000000000127753", "00000000000000077706", "00000000000000017133", "00000000000000022582", "00000000000000112132", "00000000000000027625", "00000000000000126773", "00000000000000008924", "00000000000000125972", "00000000000000002551", "00000000000000113837", "00000000000000112045", "00000000000000100953", "00000000000000077352", "00000000000000132013", "00000000000000057029", };
  // this fails too!!! BigBinaryVector a1(a1string);
  BigBinaryVector a1(a1strvec.size());

  a1.SetModulus(q1);

  for (usint i = 0; i< a1strvec.size(); i++){
	  a1.SetValAtIndex(i,a1strvec[i]);  //come on!!
  }

  std::vector<std::string> a2strvec = {"00000185225172798255", "00000098879665709163", "00003497410031351258", "00004012431933509255", "00001543020758028581", "00000135094568432141", "00003976954337141739", "00004030348521557120", "00000175940803531155", "00000435236277692967", "00003304652649070144", "00002032520019613814", "00000375749152798379", "00003933203511673255", "00002293434116159938", "00001201413067178193", };
  BigBinaryVector a2(a2strvec.size());
  a2.SetModulus(q2);

  for (usint i = 0; i< a2strvec.size(); i++){
	  a2.SetValAtIndex(i,a2strvec[i]);  //come on!!
  }


  //b:
  std::vector<std::string> b1strvec = {"00000000000000066773", "00000000000000069572", "00000000000000142134", "00000000000000141115", "00000000000000123182", "00000000000000155822", "00000000000000128147", "00000000000000094818", "00000000000000135782", "00000000000000030844", "00000000000000088634", "00000000000000099407", "00000000000000053647", "00000000000000111689", "00000000000000028502", "00000000000000026401", };
  BigBinaryVector b1(b1strvec.size());
  b1.SetModulus(q1);

  for (usint i = 0; i< b1strvec.size(); i++){
	  b1.SetValAtIndex(i,b1strvec[i]);  //come on!!
  }

  std::vector<std::string> b2strvec = {"00000698898215124963", "00000039832572186149", "00001835473200214782", "00001041547470449968", "00001076152419903743", "00000433588874877196", "00002336100673132075", "00002990190360138614", "00000754647536064726", "00000702097990733190", "00002102063768035483", "00000119786389165930", "00003976652902630043", "00003238750424196678", "00002978742255253796", "00002124827461185795", };
  BigBinaryVector b2(b2strvec.size());
  b2.SetModulus(q2);
  for (usint i = 0; i< b2strvec.size(); i++){
	  b2.SetValAtIndex(i,b2strvec[i]);  //come on!!
  }
#if 0
  //modadd:
  std::vector<std::string> BigBinaryVector sum1 = {"00000000000000030685", "00000000000000147278", "00000000000000159267", "00000000000000163697", "00000000000000071473", "00000000000000019606", "00000000000000091079", "00000000000000103742", "00000000000000097913", "00000000000000033395", "00000000000000038630", "00000000000000047611", "00000000000000154600", "00000000000000025200", "00000000000000160515", "00000000000000083430", };
  std::vector<std::string> BigBinaryVector sum2 = {"00000884123387923218", "00000138712237895312", "00001275066812033239", "00000996162984426422", "00002619173177932324", "00000568683443309337", "00002255238590741013", "00002962722462162933", "00000930588339595881", "00001137334268426157", "00001348899997572826", "00002152306408779744", "00000294585635895621", "00003114137516337132", "00001214359951880933", "00003326240528363988", };
  modsub:
std::vector<std::string>  BigBinaryVector diff1 = {"00000000000000060980", "00000000000000008134", "00000000000000038840", "00000000000000045308", "00000000000000152791", "00000000000000035644", "00000000000000162467", "00000000000000077947", "00000000000000154031", "00000000000000135548", "00000000000000025203", "00000000000000012638", "00000000000000047306", "00000000000000129504", "00000000000000103511", "00000000000000030628", };
std::vector<std::string>   BigBinaryVector diff2 = {"00003544143377206093", "00000059047093523014", "00001661936831136476", "00002970884463059287", "00000466868338124838", "00003759322113087746", "00001640853664009664", "00001040158161418506", "00003479109686999230", "00003790954706492578", "00001202588881034661", "00001912733630447884", "00000456912669701137", "00000694453087476577", "00003372508280438943", "00003134402025525199", };
  //modmul:
#endif

	std::vector<std::string> mul1strvec ={"00000000000000069404", "00000000000000064196", "00000000000000013039", "00000000000000115321", "00000000000000028519", "00000000000000151998", "00000000000000089117", "00000000000000080908", "00000000000000057386", "00000000000000039364", "00000000000000008355", "00000000000000146135", "00000000000000061336", "00000000000000031598", "00000000000000025961", "00000000000000087680", };
	BigBinaryVector mul1(mul1strvec.size());
	  mul1.SetModulus(q2);
	  for (usint i = 0; i< mul1strvec.size(); i++){
		  mul1.SetValAtIndex(i,mul1strvec[i]);  //come on!!
	  }
	std::vector<std::string> mul2strvec ={"00000585473140075497", "00003637571624495703", "00001216097920193708", "00001363577444007558", "00000694070384788800", "00002378590980295187", "00000903406520872185", "00000559510929662332", "00000322863634303789", "00001685429502680940", "00001715852907773825", "00002521152917532260", "00000781959737898673", "00002334258943108700", "00002573793300043944", "00001273980645866111", };
	BigBinaryVector mul2(mul2strvec.size());
	mul2.SetModulus(q2);
	for (usint i = 0; i< mul2strvec.size(); i++){
		mul2.SetValAtIndex(i,mul2strvec[i]);  //come on!!
	}

  BigBinaryVector c1t1,c2t1;

  TIC(t_total);

  TIC(t1);
for (usint j = 0; j< 1000; j++){
	  c1t1 = a1.ModMul(b1);
  }
  time1 = TOC(t1);
  DEBUG("t1: c1 = a1.ModMul(b1) computation time: " << "\t" << time1 << " us");

  bool good = true;

  for (usint i =0; i< c1t1.GetLength(); i++ ){
	  if (c1t1.GetValAtIndex(i) != mul1.GetValAtIndex(i)) {
		  good = good & false;
	  }
  }
  if (!good)
  	  cout << "bad multiply! "<<endl;


  TIC(t1);
for (usint j = 0; j< 1000; j++){
	c2t1 = a2.ModMul(b2);
}
  time1 = TOC(t1);
  DEBUG("t1: c2 = a2.ModMul(b2) computation time: " << "\t" << time1 << " us");

  good = true;

  for (usint i =0; i< c2t1.GetLength(); i++ ){
	  if (c2t1.GetValAtIndex(i) != mul2.GetValAtIndex(i)) {
		  good = good & false;
	  }
  }

  if (!good)
  	  cout << "bad multiply! "<<endl;

//  TIC(t1);
//  c1t2 = a1.ModMul(b1,q1);
//  time1 = TOC(t1);
//  DEBUG("t2: c1 = a1.ModMul(b1,q1) computation time: " << "\t" << time1 << " ms");
//
//  TIC(t1);
//  //c1t3 = a1.ModBarretMul(b1,q1,mu1);
//  time1 = TOC(t1);
//  DEBUG("t3: c1 = a1.ModBarretMul(b1,q1,mu1) computation time: " << "\t" << time1 << " ms");


  //cout << "c1t2: " << c1t2 << endl;
  //cout << "c1t3: " << c1t3 << endl;

  timeTotal = TOC(t_total);
  DEBUG("Total time: " << "\t" << timeTotal << " us");



  return 0;
}

