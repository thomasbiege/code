#include <DigiMouse.h>
#include <oddebug.h>
#include <osccal.h>
#include <osctune.h>
#include <usbconfig.h>
#include <usbconfig-prototype.h>
#include <usbdrv.h>
#include <usbportability.h>




void setup() {
  // put your setup code here, to run once:
  DigiMouse.begin();
}

void loop() {
  // put your main code here, to run repeatedly:
  // circle around to keep the mouse pointer moving and to avoid the screen saver
  DigiMouse.moveY(10); // down 10
  DigiMouse.delay(500);
  DigiMouse.moveX(10); //right 10
  DigiMouse.delay(500);
  DigiMouse.moveY(-10); // up 10
  DigiMouse.delay(500);
  DigiMouse.moveX(-10); // left 10
  DigiMouse.delay(500);

}
