/**
 * autopasswd – On the fly password generator
 * 
 * Copyright © 2014  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <passphrase.h>

#include "sha3.h"



/**
 * Prompt string that tells you to enter your master passphrase
 */
#ifndef PASSPHRASE_PROMPT_STRING
# define PASSPHRASE_PROMPT_STRING  "[autopasswd] Enter master passphrase: "
# warning: you should personalise PASSPHRASE_PROMPT_STRING.
#endif

/**
 * Prompt string that tells you to enter site
 */
#ifndef SITE_PROMPT_STRING
# define SITE_PROMPT_STRING  "[autopasswd] Enter site: "
#endif



#ifndef KECCAK_OUTPUT
# define KECCAK_OUTPUT  512
#endif
#ifndef KECCAK_BITRATE
# define KECCAK_BITRATE  (KECCAK_OUTPUT * 2)
#endif
#ifndef KECCAK_CAPACITY
# define KECCAK_CAPACITY  (1600 - KECCAK_BITRATE)
#endif

#ifndef KECCAK_SQUEEZES
# define KECCAK_SQUEEZES  300000
#endif

#define KECCAK_BYTE_OUTPUT  ((KECCAK_OUTPUT + 7) / 8)

#ifndef BASE64
# define BASE64 "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM,.-="
#endif



int main(int argc, char** argv)
{
  size_t ptr = 0;
  size_t site_size = 64;
  char* site;
  char* passphrase;
  uint8_t* digest;
  char* base64;
  size_t ptr64;
  
  /* Read site. */
  site = malloc(site_size * sizeof(char));
  if (site == NULL)
    {
      perror(*argv);
      return 1;
    }
  fprintf(stderr, "%s", SITE_PROMPT_STRING);
  fflush(stderr);
  for (;;)
    {
      int c = getchar();
      if (c == -1)
	{
	  free(site);
	  return 0;
	}
      if (c == '\n')
	{
	  *(site + ptr) = 0;
	  break;
	}
      *(site + ptr++) = (char)c;
    }
  
  /* Disable echoing. (Should be done as soon as possible.) */
  passphrase_disable_echo();
  
  /* Initialise Keccak sponge. */
  sha3_initialise(KECCAK_BITRATE, KECCAK_CAPACITY, KECCAK_OUTPUT);
  
  /* Read passphrease. */
  fprintf(stderr, "%s", PASSPHRASE_PROMPT_STRING);
  fflush(stderr);
  passphrase = passphrase_read();
  if (passphrase == NULL)
    {
      perror(*argv);
      passphrase_reenable_echo();
      sha3_dispose();
      free(site);
      return 1;
    }
  
  /* Reset terminal settings. */
  passphrase_reenable_echo();
  
  /* Add passphrase to Keccak sponge input. */
  sha3_update(passphrase, strlen(passphrase));
  
  /* Clear passphrase from memory. (Should be done as sone as possible.) */
  memset(passphrase, 0, strlen(passphrase));
  free(passphrase);
  
  /* Add site to Keccak sponge input. */
  sha3_digest(site, strlen(site), 0);
  
  /* Release resources. */
  free(site);
  
  /* Squeeze that sponge. */
  sha3_fastSqueeze(KECCAK_SQUEEZES);
  digest = sha3_squeeze();
  
  /* Release resources. */
  sha3_dispose();
  
  /* Encode with base64 (no invalid character, shorter than hexadecimal.) */
  base64 = malloc((4 * ((KECCAK_BYTE_OUTPUT + 2) / 3) + 2) * sizeof(char));
  if (base64 == NULL)
    {
      perror(*argv);
      free(digest);
      free(base64);
    }
  for (ptr = ptr64 = 0; ptr < KECCAK_BYTE_OUTPUT; ptr64 += 4)
    {
      uint32_t a = ptr < KECCAK_BYTE_OUTPUT ? digest[ptr++] : 0;
      uint32_t b = ptr < KECCAK_BYTE_OUTPUT ? digest[ptr++] : 0;
      uint32_t c = ptr < KECCAK_BYTE_OUTPUT ? digest[ptr++] : 0;
      
      uint32_t abc = (a << 16) | (b << 8) | (c << 0);
      
      base64[ptr64 | 0] = BASE64[(abc >> (3 * 6)) & 63];
      base64[ptr64 | 1] = BASE64[(abc >> (2 * 6)) & 63];
      base64[ptr64 | 2] = BASE64[(abc >> (1 * 6)) & 63];
      base64[ptr64 | 3] = BASE64[(abc >> (0 * 6)) & 63];
    }
  if ((KECCAK_BYTE_OUTPUT % 3) == 1)  base64[ptr64++] = BASE64[64];
  if ((KECCAK_BYTE_OUTPUT % 3) == 2)  base64[ptr64++] = BASE64[65];
  base64[ptr64++] = 0;
  
  /* Print generated password. */
  printf("\033[00m>\033[00;30;40m%s\033[00m<\n", base64);
  
  /* Release resources. */
  free(digest);
  free(base64);
  
  return 0;
}

