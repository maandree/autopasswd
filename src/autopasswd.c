/**
 * autopasswd – Reproducable password generator
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
#include <argparser.h>

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

/**
 * The radix 64 characters (66 characters), the two last ones are for padding
 */
#ifndef BASE64
# define BASE64 "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM,.-="
#endif

/**
 * The number of squeezes to do at bump level zero
 */
#ifndef KECCAK_SQUEEZES
# define KECCAK_SQUEEZES  300000
#endif

/**
 * The default output parameter for the Keccak sponge
 */
#ifndef KECCAK_OUTPUT
# define KECCAK_OUTPUT  512
#endif

/**
 * The default state size parameter for the Keccak sponge
 */
#ifndef KECCAK_STATE_SIZE
# define KECCAK_STATE_SIZE  1600
#endif

/**
 * The number of addition squeezes to perform per bump level
 */
#ifndef BUMP_LEVEL_MULTIPLIER
# define BUMP_LEVEL_MULTIPLIER  5000
#endif


/**
 * The bitrate parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef MASTER_PASSPHRASE_KECCAK_BITRATE
# define MASTER_PASSPHRASE_KECCAK_BITRATE  576
#endif

/**
 * The capacity parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef MASTER_PASSPHRASE_KECCAK_CAPACITY
# define MASTER_PASSPHRASE_KECCAK_CAPACITY  1024
#endif

/**
 * The output parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef MASTER_PASSPHRASE_KECCAK_OUTPUT
# define MASTER_PASSPHRASE_KECCAK_OUTPUT  32
#endif

/**
 * The number of times to squeeze the master passphrase
 */
#ifndef MASTER_PASSPHRASE_KECCAK_SQUEEZES
# define MASTER_PASSPHRASE_KECCAK_SQUEEZES  10000
#endif

/**
 * The hexadecimal alphabet
 */
#ifndef HEXADECA
# define HEXADECA  "0123456789abcdef"
#endif



static char* last_arg(char* arg)
{
  return *(args_opts_get(arg) + (args_opts_get_count(arg) - 1));
}


/**
 * Here we go!
 */
int main(int argc, char** argv)
{
  size_t site_size = 64;
  long bump_level = 0;
  int clear_mode = 0;
  int verbose_mode = 0;
  long keccak_output_ = KECCAK_OUTPUT;
  long keccak_state_size_ = KECCAK_STATE_SIZE;
  long keccak_capacity_ = keccak_state_size_ - (keccak_output_ << 1);
  long keccak_bitrate_ = keccak_state_size_ - keccak_capacity_;
  long keccak_squeezes = KECCAK_SQUEEZES;
  int output__ = 0;
  int state_size__ = 0;
  int capacity__ = 0;
  int bitrate__ = 0;
  int word_size__ = 0;
  int squeezes__ = 0;
  long output_, keccak_output;
  long state_size_, keccak_state_size;
  long capacity_, keccak_capacity;
  long bitrate_, keccak_bitrate;
  long word_size_, keccak_word_size;
  long squeezes_;
  byte* site;
  char* passphrase;
  byte* passphrase_hash;
  int_fast8_t* digest;
  char* base64;
  size_t ptr64;
  size_t ptr;
  char* master_passphrase_hash;
  size_t passphrase_n;
  size_t site_n;
  
  
  /* Parse command line arguments. */
  args_init("Reproducable password generator", "autopasswd [options...]",
	    "TODO", 0, 1, 0, args_standard_abbreviations);
  
  args_add_option(args_new_argumentless(NULL, 0, "-h", "-?", "--help", NULL),
		  "Display this help message");
  args_add_option(args_new_argumentless(NULL, 0, "+c", "--copyright", "--copying", NULL),
		  "Display copyright information");
  args_add_option(args_new_argumentless(NULL, 0, "+w", "--warranty", NULL),
		  "Display warranty disclaimer");
  args_add_option(args_new_argumentless(NULL, 0, "-v", "--verbose", NULL),
		  "Display extra information");
  args_add_option(args_new_argumented(NULL, "INT", 0, "-b", "--bump-level", NULL),
		  "Select bump level, can contain + or - to perform accumulated adjustment");
  args_add_option(args_new_argumentless(NULL, 0, "-c", "--clear-mode", NULL),
		  "Do not hide the output, but rather make it ease to pass into another program\n"
		  "Use twice to suppress terminal line break");
  args_add_option(args_new_argumented(NULL, "INT", 0, "-O", "--output", NULL),
		  "Select output parameter for Keccak sponge");
  args_add_option(args_new_argumented(NULL, "INT", 0, "-S", "--state-size", NULL),
		  "Select state size parameter for Keccak sponge");
  args_add_option(args_new_argumented(NULL, "INT", 0, "-C", "--capacity", NULL),
		  "Select capacity parameter for Keccak sponge");
  args_add_option(args_new_argumented(NULL, "INT", 0, "-R", "--rate", "--bitrate", NULL),
		  "Select bitrate parameter for Keccak sponge");
  args_add_option(args_new_argumented(NULL, "INT", 0, "-W", "--word-size", NULL),
		  "Select word size parameter for Keccak sponge");
  args_add_option(args_new_argumented(NULL, "INT", 0, "-Z", "--squeezes", NULL),
		  "Select the number squeezes performe on the Keccak sponge at bump level zero");
  
  args_parse(argc, argv);
  args_support_alternatives();
  
  if (args_opts_used("--help"))
    {
      args_help();
      args_dispose();
      return 0;
    }
  if (args_opts_used("--copyright"))
    {
      printf("autopasswd – Reproducable password generator\n");
      printf("\n");
      printf("Copyright © 2014  Mattias Andrée (maandree@member.fsf.org)\n");
      printf("\n");
      printf("This program is free software: you can redistribute it and/or modify\n");
      printf("it under the terms of the GNU Affero General Public License as published by\n");
      printf("the Free Software Foundation, either version 3 of the License, or\n");
      printf("(at your option) any later version.\n");
      printf("\n");
      printf("This program is distributed in the hope that it will be useful,\n");
      printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
      printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
      printf("GNU Affero General Public License for more details.\n");
      printf("\n");
      printf("You should have received a copy of the GNU Affero General Public License\n");
      printf("along with this program.  If not, see <http://www.gnu.org/licenses/>.\n");
      args_dispose();
      return 0;
    }
  if (args_opts_used("--warranty"))
    {
      printf("This program is distributed in the hope that it will be useful,\n");
      printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
      printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
      printf("GNU Affero General Public License for more details.\n");
      args_dispose();
      return 0;
    }
  if (args_opts_used("--clear-mode"))
    {
      clear_mode = (int)args_opts_get_count("--clear-mode");
    }
  if (args_opts_used("--verbose"))
    {
      verbose_mode = 1;
    }
  if (args_opts_used("--bump-level"))
    {
      size_t n = (size_t)args_opts_get_count("--bump-level");
      char** arr = args_opts_get("--bump-level");
      char* arg;
      for (ptr = 0; ptr < n; ptr++)
	if ((arg = *(arr + ptr)))
	  switch (*arg)
	    {
	    case 0:
	      break;
	    case '+':
	      bump_level += atol(arg + 1);
	      break;
	    case '-':
	      bump_level -= atol(arg + 1);
	      break;
	    default:
	      bump_level = atol(arg);
	      break;
	    }
    }
  if (args_opts_used("--output"))
    {
      output__ = 1;
      output_ = atol(last_arg("--output"));
    }
  if (args_opts_used("--state-size"))
    {
      state_size__ = 1;
      state_size_ = atol(last_arg("--state-size"));
    }
  if (args_opts_used("--capacity"))
    {
      capacity__ = 1;
      capacity_ = atol(last_arg("--capacity"));
    }
  if (args_opts_used("--bitrate"))
    {
      bitrate__ = 1;
      bitrate_ = atol(last_arg("--bitrate"));
    }
  if (args_opts_used("--word-size"))
    {
      word_size__ = 1;
      word_size_ = atol(last_arg("--word-size"));
    }
  if (args_opts_used("--squeezes"))
    {
      squeezes__ = 1;
      squeezes_ = atol(last_arg("--squeezes"));
    }
  
  args_dispose();
  
  /* Get Keccak sponge parameters. */
  if (squeezes__)
    {
      keccak_squeezes = squeezes_;
      if (keccak_squeezes == 0)
	{
	  fprintf(stderr, "%s: do you really want your passphrase included in plain text?", *argv);
	  return 1;
	}
      else if (keccak_squeezes < 1)
	{
	  fprintf(stderr, "%s: the squeeze count must be positive.", *argv);
	  return 1;
	}
    }
  if (state_size__)
    {
      keccak_state_size = state_size_;
      if ((keccak_state_size <= 0) || (keccak_state_size > 1600) || (keccak_state_size % 25))
	{
	  fprintf(stderr, "%s: the state size must be a positive multiple of 25 and is limited to 1600.", *argv);
	  return 1;
	}
    }
  if (word_size__)
    {
      keccak_word_size = word_size_;
      if ((keccak_word_size <= 0) || (keccak_word_size > 64))
	{
	  fprintf(stderr, "%s: the word size must be positive and is limited to 64.", *argv);
	  return 1;
	}
      if (state_size__ && (keccak_state_size != keccak_word_size * 25))
	{
	  fprintf(stderr, "%s: the state size must be 25 times of the word size.", *argv);
	  return 1;
	}
      else if (state_size__ == 0)
	{
	  state_size__ = 1;
	  keccak_state_size = keccak_word_size * 25;
	}
    }
  if (capacity__)
    {
      keccak_capacity = capacity_;
      if ((keccak_capacity <= 0) || (keccak_capacity & 7))
	{
	  fprintf(stderr, "%s: the capacity must be a positive multiple of 8.", *argv);
	  return 1;
	}
    }
  if (bitrate__)
    {
      keccak_bitrate = bitrate_;
      if ((keccak_bitrate <= 0) || (keccak_bitrate & 7))
	{
	  fprintf(stderr, "%s: the bitrate must be a positive multiple of 8.", *argv);
	  return 1;
	}
    }
  if (output__)
    {
      keccak_output = output_;
      if (keccak_output <= 0)
	{
	  fprintf(stderr, "%s: the output size must be positive.", *argv);
	  return 1;
	}
    }
  if ((bitrate__ & capacity__ & output__) == 0) /* state_size? */
    {
      keccak_state_size = state_size__ ? keccak_state_size : keccak_state_size_;
      keccak_output = (((keccak_state_size << 5) / 100 + 7) >> 3) << 3;
      keccak_bitrate = keccak_output << 1;
      keccak_capacity = keccak_state_size - keccak_bitrate;
      keccak_output = keccak_output < 8 ? 8 : keccak_output;
    }
  else if ((bitrate__ & capacity__) == 0) /* !output state_size? */
    {
      keccak_bitrate = keccak_bitrate_;
      keccak_capacity = keccak_capacity_;
      keccak_state_size = state_size__ ? keccak_state_size : (keccak_bitrate + keccak_capacity);
    }
  else if (bitrate__ == 0) /* !bitrate output? state_size? */
    {
      keccak_state_size = state_size__ ? keccak_state_size : keccak_state_size_;
      keccak_bitrate = keccak_state_size - keccak_capacity;
      keccak_output = output__ ? keccak_output : (keccak_capacity == 8 ? 8 : (keccak_capacity << 1));
    }
  else if (capacity__ == 0) /* !bitrate output? state_size? */
    {
      keccak_state_size = state_size__ ? keccak_state_size : keccak_state_size_;
      keccak_capacity = keccak_state_size - keccak_bitrate;
      keccak_output = output__ ? keccak_output : (keccak_capacity == 8 ? 8 : (keccak_capacity << 1));
    }
  else /* !bitrate !capacity output? state_size? */
    {
      keccak_state_size = state_size__ ? keccak_state_size : (keccak_bitrate + keccak_capacity);
      keccak_output = output__ ? keccak_output : (keccak_capacity == 8 ? 8 : (keccak_capacity << 1));
    }
  if (keccak_bitrate > keccak_state_size)
    {
      fprintf(stderr, "%s: the bitrate must not be higher than the state size.", *argv);
      return 1;
    }
  if (keccak_capacity > keccak_state_size)
    {
      fprintf(stderr, "%s: the capacity must not be higher than the state size.", *argv);
      return 1;
    }
  if (keccak_bitrate + keccak_capacity != keccak_state_size)
    {
      fprintf(stderr, "%s: the sum of the bitrate and the capacity must equal the state size.", *argv);
      return 1;
    }
  keccak_squeezes += bump_level * BUMP_LEVEL_MULTIPLIER;
  if (keccak_squeezes < 1)
    {
      fprintf(stderr, "%s: bump level is too low.", *argv);
      return 1;
    }
  keccak_word_size = keccak_state_size / 25;
  
  /* Display verbose information. */
  if (verbose_mode)
    {
      fprintf(stderr, "Bump level: %li\n", bump_level);
      fprintf(stderr, "Bitrate: %li\n", keccak_bitrate);
      fprintf(stderr, "Capacity: %li\n", keccak_capacity);
      fprintf(stderr, "Word size: %li\n", keccak_word_size);
      fprintf(stderr, "State size: %li\n", keccak_state_size);
      fprintf(stderr, "Output size: %li\n", keccak_output);
      fprintf(stderr, "Squeezes (excluding bump level): %li\n",
	      keccak_squeezes - bump_level * BUMP_LEVEL_MULTIPLIER);
      fprintf(stderr, "Squeezes (including bump level): %li\n", keccak_squeezes);
    }
  
  /* Read site. */
  site = malloc(site_size * sizeof(byte));
  if (site == NULL)
    {
      perror(*argv);
      passphrase_disable_echo();
      return 1;
    }
  fprintf(stderr, "%s", SITE_PROMPT_STRING);
  fflush(stderr);
  for (site_n = 0;;)
    {
      int c = getchar();
      if (site_n == site_size)
	{
	  site = realloc(site, (site_size <<= 1) * sizeof(byte));
	  if (site == NULL)
	    {
	      perror(*argv);
	      passphrase_disable_echo();
	      return 1;
	    }
	}
      if (c == -1)
	{
	  free(site);
	  passphrase_disable_echo();
	  return 0;
	}
      if (c == '\n')
	break;
      *(site + site_n++) = (byte)c;
    }
  
  /* Disable echoing. (Should be done as soon as possible after reading site.) */
  passphrase_disable_echo();
  
  /* Initialise Keccak sponge. */
  sha3_initialise(MASTER_PASSPHRASE_KECCAK_BITRATE,
		  MASTER_PASSPHRASE_KECCAK_CAPACITY,
		  MASTER_PASSPHRASE_KECCAK_OUTPUT);
  
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
  
  /* Measure passphrase length. */
  passphrase_n = strlen(passphrase);
  
  /* Translate password to sha3.h friendly format. */
  passphrase_hash = malloc((passphrase_n + 1) * sizeof(byte));
  if (passphrase_hash == NULL)
    {
      perror(*argv);
      memset(passphrase, 0, passphrase_n * sizeof(char));
      free(passphrase);
      return 1;
    }
  else
    {
      for (ptr = 0; ptr < passphrase_n + 1; ptr++)
	*(passphrase_hash + ptr) = (byte)*(passphrase + ptr);
      /* Wipe source password, however it is not yet secure to free it. (Should be done as sone as possible.) */
      memset(passphrase, 0, passphrase_n * sizeof(char));
    }
  
  /* Hash and display master passphrase so hint the user whether it as typed correctly or not. */
  master_passphrase_hash = malloc((MASTER_PASSPHRASE_KECCAK_OUTPUT * 2 + 1) * sizeof(char));
  if (master_passphrase_hash == NULL)
    {
      perror(*argv);
      memset(passphrase_hash, 0, passphrase_n * sizeof(byte));
      free(passphrase_hash);
      free(passphrase);
      return 1;
    }
  digest = sha3_digest(passphrase_hash, (long)passphrase_n, MASTER_PASSPHRASE_KECCAK_SQUEEZES == 1);
  if (MASTER_PASSPHRASE_KECCAK_SQUEEZES > 2)
    sha3_fastSqueeze(MASTER_PASSPHRASE_KECCAK_SQUEEZES - 2);
  if (MASTER_PASSPHRASE_KECCAK_SQUEEZES > 1)
    digest = sha3_squeeze();
  for (ptr = 0; ptr < (MASTER_PASSPHRASE_KECCAK_OUTPUT + 7) / 8; ptr++)
    {
      uint8_t v = (uint8_t)*(digest + ptr);
      *(master_passphrase_hash + ptr * 2 + 0) = HEXADECA[(v >> 4) & 15];
      *(master_passphrase_hash + ptr * 2 + 1) = HEXADECA[(v >> 0) & 15];
    }
  *(master_passphrase_hash + ptr * 2) = 0;
  fprintf(stderr, "%s: master passphrase hash: %s\n", *argv, master_passphrase_hash);
  
  /* Reinitialise Keccak sponge. */
  sha3_dispose();
  sha3_initialise(keccak_bitrate, keccak_capacity, keccak_output);
  
  /* Add passphrase to Keccak sponge input. */
  sha3_update(passphrase_hash, (long)passphrase_n);
  
  /* Clear passphrase from memory. (Should be done as sone as possible.) */
  memset(passphrase, 0, passphrase_n * sizeof(char));
  free(passphrase_hash);
  free(passphrase);
  
  /* Add site to Keccak sponge input. */
  free(digest); /* (Should be done after wiping passphrase.) */
  free(master_passphrase_hash); /* (Should be done after wiping passphrase.) */
  digest = sha3_digest(site, (long)site_n, keccak_squeezes == 1);
  
  /* Release resources. */
  free(site);
  
  /* Squeeze that sponge. */
  if (keccak_squeezes > 2)
    sha3_fastSqueeze(keccak_squeezes - 2);
  if (keccak_squeezes > 1)
    digest = sha3_squeeze();
  
  /* Release resources. */
  sha3_dispose();
  
  /* Encode with base64 (no invalid character, shorter than hexadecimal.) */
  base64 = malloc((4 * (((((size_t)keccak_output + 7) / 8) + 2) / 3) + 2) * sizeof(char));
  if (base64 == NULL)
    {
      perror(*argv);
      free(digest);
      free(base64);
    }
  for (ptr = ptr64 = 0; ptr < (size_t)((keccak_output + 7) / 8); ptr64 += 4)
    {
      uint8_t a = (uint8_t)(ptr < (size_t)((keccak_output + 7) / 8) ? digest[ptr++] : 0);
      uint8_t b = (uint8_t)(ptr < (size_t)((keccak_output + 7) / 8) ? digest[ptr++] : 0);
      uint8_t c = (uint8_t)(ptr < (size_t)((keccak_output + 7) / 8) ? digest[ptr++] : 0);
      
      uint32_t abc = ((uint32_t)a << 16) | ((uint32_t)b << 8) | ((uint32_t)c << 0);
      
      base64[ptr64 | 0] = BASE64[(abc >> (3 * 6)) & 63];
      base64[ptr64 | 1] = BASE64[(abc >> (2 * 6)) & 63];
      base64[ptr64 | 2] = BASE64[(abc >> (1 * 6)) & 63];
      base64[ptr64 | 3] = BASE64[(abc >> (0 * 6)) & 63];
    }
  if ((((keccak_output + 7) / 8) % 3) == 1)  base64[ptr64++] = BASE64[64];
  if ((((keccak_output + 7) / 8) % 3) == 2)  base64[ptr64++] = BASE64[65];
  base64[ptr64++] = 0;
  
  /* Display verbose information. */
  if (verbose_mode)
    {
      fprintf(stderr, "Password length (before base64): %li\n", (keccak_output + 7) / 8);
      fprintf(stderr, "Password length (after base64): %li\n", strlen(base64));
    }
  
  /* Print generated password. */
  if (clear_mode > 1)
    printf("%s", base64);
  else if (clear_mode)
    printf("%s\n", base64);
  else
    printf("\033[00m>\033[00;30;40m%s\033[00m<\n", base64);
  
  /* Release resources. */
  free(digest);
  free(base64);
  
  return 0;
}

