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
#include <libkeccak.h>



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
#define BASE64  "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM,.-="

/**
 * The number of squeezes to do at bump level zero
 */
#define DEFAULT_SQUEEZES  300000

/**
 * The number of addition squeezes to perform per bump level
 */
#define BUMP_LEVEL_MULTIPLIER  5000


/**
 * The rate parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef MASTER_PASSPHRASE_KECCAK_RATE
# define MASTER_PASSPHRASE_KECCAK_RATE  576
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



#define USER_ERROR(string)				\
  (fprintf(stderr, "%s: %s.\n", execname, string), 1)

#define ADD(arg, desc, ...)								\
  (arg ? args_add_option(args_new_argumented(NULL, arg, 0, __VA_ARGS__, NULL), desc)	\
   : args_add_option(args_new_argumentless(NULL, 0, __VA_ARGS__, NULL), desc))

#define LAST(arg)					\
  (args_opts_get(arg)[args_opts_get_count(arg) - 1])

#define t(expr)  if ((r = (expr)))  goto fail

#define xfree(s)  (free(s), s = NULL)



/**
 * `argv[0]` from `main`
 */
static char* execname;



/**
 * Convert `libkeccak_generalised_spec_t` to `libkeccak_spec_t` and check for errors
 * 
 * @param   gspec  See `libkeccak_degeneralise_spec`
 * @param   spec   See `libkeccak_degeneralise_spec`
 * @return         Zero on success, an appropriate exit value on error
 */
static int make_spec(libkeccak_generalised_spec_t* gspec, libkeccak_spec_t* spec)
{
  int r;
  
#define TEST(CASE, STR)  case LIBKECCAK_GENERALISED_SPEC_ERROR_##CASE:  return USER_ERROR(STR)
  if (r = libkeccak_degeneralise_spec(gspec, spec), r)
    switch (r)
      {
      TEST (STATE_NONPOSITIVE,      "the state size must be positive");
      TEST (STATE_TOO_LARGE,        "the state size is too large, may not exceed 1600");
      TEST (STATE_MOD_25,           "the state size must be a multiple of 25");
      TEST (WORD_NONPOSITIVE,       "the word size must be positive");
      TEST (WORD_TOO_LARGE,         "the word size is too large, may not exceed 64");
      TEST (STATE_WORD_INCOHERENCY, "the state size must be exactly 25 times the word size");
      TEST (CAPACITY_NONPOSITIVE,   "the capacity must be positive");
      TEST (CAPACITY_MOD_8,         "the capacity must be a multiple of 8");
      TEST (BITRATE_NONPOSITIVE,    "the rate must be positive");
      TEST (BITRATE_MOD_8,          "the rate must be a multiple of 8");
      TEST (OUTPUT_NONPOSITIVE,     "the output size must be positive");
      default:
	return USER_ERROR("unknown error in algorithm parameters");
      }
#undef TEST
  
#define TEST(CASE, STR)  case LIBKECCAK_SPEC_ERROR_##CASE:  return USER_ERROR(STR)
  if (r = libkeccak_spec_check(spec), r)
    switch (r)
      {
      TEST (BITRATE_NONPOSITIVE,  "the rate size must be positive");
      TEST (BITRATE_MOD_8,        "the rate must be a multiple of 8");
      TEST (CAPACITY_NONPOSITIVE, "the capacity must be positive");
      TEST (CAPACITY_MOD_8,       "the capacity must be a multiple of 8");
      TEST (OUTPUT_NONPOSITIVE,   "the output size must be positive");
      TEST (STATE_TOO_LARGE,      "the state size is too large, may not exceed 1600");
      TEST (STATE_MOD_25,         "the state size must be a multiple of 25");
      TEST (WORD_NON_2_POTENT,    "the word size must be a power of 2");
      TEST (WORD_MOD_8,           "the word size must be a multiple of 8");
      default:
	return USER_ERROR("unknown error in algorithm parameters");
      }
#undef TEST
  
  return 0;
}


/**
 * Parse the command line arguments
 * 
 * @param   argc        The number of command line argumnets
 * @param   argv        Command line argumnets
 * @param   gspec       Output parameter for the algorithm parameters, must already be initialised
 * @param   squeezes    Output parameter for the number of squeezes to perform, must already have default value
 * @param   bump_level  Output parameter for the bump level, must already be zero
 * @param   clear_mode  Output parameter for the clear mode setting, must already be zero
 * @param   verbose     Output parameter for the verbosity setting, must already be zero
 * @return              Zero on success, an appropriate exit value on error, however -1 if
 *                      the program should exit with value zero
 */
static int parse_cmdline(int argc, char* argv[], libkeccak_generalised_spec_t* gspec,
			 long* squeezes, long* bump_level, int* clear_mode, int* verbose)
{
  args_init("Reproducable password generator", "autopasswd [options...]",
	    NULL, NULL, 1, 0, args_standard_abbreviations);
  
  ADD(NULL,       "Display option summary",                         "-h", "-?", "--help");
  ADD(NULL,       "Display copyright information",                  "+c", "--copyright", "--copying");
  ADD(NULL,       "Display warranty disclaimer",                    "+w", "--warranty");
  ADD(NULL,       "Display extra information",                      "-v", "--verbose");
  ADD(NULL,       "Do not hide the output, but rather make it ease to pass into another program\n"
                  "Use twice to suppress terminal line break",      "-c", "--clear-mode");
  ADD("LEVEL",    "Select bump level, can contain + or - to perform accumulated adjustment",
                                                                    "-b", "--bump-level");
  ADD("RATE",     "Select rate parameter for Keccak sponge",        "-R", "--bitrate", "--rate");
  ADD("CAPACITY", "Select capacity parameter for Keccak sponge",    "-C", "--capacity");
  ADD("SIZE",     "Select output parameter for Keccak sponge",      "-N", "-O", "--output-size", "--output");
  ADD("SIZE",     "Select state size parameter for Keccak sponge",  "-S", "-B", "--state-size", "--state");
  ADD("SIZE",     "Select word size parameter for Keccak sponge",   "-W", "--word-size", "--word");
  ADD("COUNT",    "Select the number squeezes performed on the Keccak sponge at bump level zero",
                                                                    "-Z", "--squeezes");
  
  args_parse(argc, argv);
  
  if (args_opts_used("-h"))  return args_help(0), args_dispose(), -1;
  if (args_opts_used("+c"))
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
      return -1;
    }
  if (args_opts_used("+w"))
    {
      printf("This program is distributed in the hope that it will be useful,\n");
      printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
      printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
      printf("GNU Affero General Public License for more details.\n");
      args_dispose();
      return -1;
    }
  
  if (args_opts_used("-R"))  gspec->bitrate    = atol(LAST("-R"));
  if (args_opts_used("-C"))  gspec->capacity   = atol(LAST("-C"));
  if (args_opts_used("-N"))  gspec->output     = atol(LAST("-N"));
  if (args_opts_used("-S"))  gspec->state_size = atol(LAST("-S"));
  if (args_opts_used("-W"))  gspec->word_size  = atol(LAST("-W"));
  if (args_opts_used("-Z"))  *squeezes         = atol(LAST("-Z"));
  if (args_opts_used("-v"))  *verbose          = 1;
  if (args_opts_used("-c"))  *clear_mode       = (int)args_opts_get_count("-c");
  if (args_opts_used("-b"))
    {
      size_t i, n = (size_t)args_opts_get_count("-b");
      char** arr = args_opts_get("-b");
      char* arg;
      for (i = 0; i < n; i++)
	if ((arg = arr[i]))
	  switch (*arg)
	    {
	    case 0:                                   break;
	    case '+':  *bump_level += atol(arg + 1);  break;
	    case '-':  *bump_level -= atol(arg + 1);  break;
	    default:   *bump_level = atol(arg);       break;
	    }
    }
  
  args_dispose();
  return 0;
}


/**
 * Hash, and display, master passphrase so to hint
 * the user whether it as typed correctly or not
 * (important when creating a passphrase)
 * 
 * @param   passphrase  The master passphrase
 * @return              Zero on success, an appropriate exit value on error
 */
static int hash_master_passphrase(const char* passphrase)
{
#define SQUEEZES  MASTER_PASSPHRASE_KECCAK_SQUEEZES
  libkeccak_spec_t spec;
  libkeccak_state_t state;
  char hashsum[MASTER_PASSPHRASE_KECCAK_OUTPUT / 8];
  char hexsum[MASTER_PASSPHRASE_KECCAK_OUTPUT / 4 + 1];
  
  spec.bitrate = MASTER_PASSPHRASE_KECCAK_RATE;
  spec.capacity = MASTER_PASSPHRASE_KECCAK_CAPACITY;
  spec.output = MASTER_PASSPHRASE_KECCAK_OUTPUT;
  
  if (libkeccak_spec_check(&spec) || (SQUEEZES <= 0))
    return USER_ERROR("bad master passhprase hashing parameters, "
		      "please recompile autopasswd with with proper "
		      "values on MASTER_PASSPHRASE_KECCAK_RATE, "
		      "MASTER_PASSPHRASE_KECCAK_CAPACITY, "
		      "MASTER_PASSPHRASE_KECCAK_OUTPUT and "
		      "MASTER_PASSPHRASE_KECCAK_SQUEEZES");
  
  if (libkeccak_state_initialise(&state, &spec))
    return perror(execname), 2;
  
  if (libkeccak_digest(&state, passphrase, strlen(passphrase), 0, NULL, SQUEEZES == 1 ? hashsum : NULL))
    return perror(execname), libkeccak_state_destroy(&state), 2;
  if (SQUEEZES > 2)  libkeccak_fast_squeeze(&state, SQUEEZES - 2);
  if (SQUEEZES > 1)  libkeccak_squeeze(&state, hashsum);
  
  libkeccak_state_destroy(&state);
  
  libkeccak_behex_lower(hexsum, hashsum, sizeof(hashsum) / sizeof(char));
  fprintf(stderr, "%s: master passphrase hash: %s\n", execname, hexsum);
  
  return 0;
#undef SQUEEZES
}


/**
 * Ask the user for the site
 * 
 * @param   site  Output parameter for the site
 * @return        Zero on success, an appropriate exit value on error
 */
static int get_site(char** site)
{
  size_t size = 64;
  size_t ptr = 0;
  char* buf = malloc(size * sizeof(char));
  if (buf == NULL)
    return perror(execname), 2;
  
  fprintf(stderr, "%s", SITE_PROMPT_STRING);
  fflush(stderr);
  
  for (;;)
    {
      int c = getchar();
      if (ptr == size)
	{
	  char* new = realloc(buf, (size <<= 1) * sizeof(char));
	  if (new == NULL)
	    return perror(execname), free(buf), 2;
	}
      if ((c < 0) || (c == '\n'))
	break;
      buf[ptr++] = (char)c;
    }
  
  if (ptr == size)
    {
      char* new = realloc(buf, (size += 1) * sizeof(char));
      if (new == NULL)
	return perror(execname), free(buf), 2;
    }
  buf[ptr] = '\0';
  
  *site = buf;
  return 0;
}


/**
 * Ask the user for the master passphrase
 * 
 * @param   passphrase  Output parameter for the passphrase
 * @return              Zero on success, an appropriate exit value on error
 */
static int get_master_passphrase(char** passphrase)
{
  passphrase_disable_echo();
  fprintf(stderr, "%s", PASSPHRASE_PROMPT_STRING);
  fflush(stderr);
  *passphrase = passphrase_read();
  if (*passphrase == NULL)
    perror(execname);
  passphrase_reenable_echo();
  return *passphrase ? 0 : 2;
}


/**
 * Hash the master password hash and site into a password
 * 
 * @param   spec        Hashing parameters
 * @param   squeezes    The number of squeezes to perform
 * @param   passphrase  The master passphrase
 * @param   site        The site
 * @param   hash        Output paramter for the raw password
 * @return              Zero on success, an appropriate exit value on error
 */
static int calculate_raw_password(const libkeccak_spec_t* spec, long squeezes,
				  const char* passphrase, const char* site, char** hash)
{
  libkeccak_state_t state;
  char* hashsum = NULL;
  
  if (libkeccak_state_initialise(&state, spec))
    return perror(execname), 2;
  
  if (hashsum = malloc((size_t)(spec->output / 8) * sizeof(char)), hashsum == NULL)
    goto fail;
  
  if (libkeccak_update(&state, passphrase, strlen(passphrase)))
    goto fail;
  if (libkeccak_digest(&state, site, strlen(site), 0, NULL, squeezes == 1 ? hashsum : NULL))
    goto fail;
  if (squeezes > 2)  libkeccak_fast_squeeze(&state, squeezes - 2);
  if (squeezes > 1)  libkeccak_squeeze(&state, hashsum);
  
  libkeccak_state_destroy(&state);
  *hash = hashsum;
  return 0;
 fail:
  perror(execname);
  free(hashsum);
  libkeccak_state_destroy(&state);
  return 2;
}


/**
 * base64-encode the password
 * 
 * @param   raw     The password
 * @param   length  The length of the pasword
 * @param   base64  Output parameter for the base64-encoded password
 * @return          Zero on success, an appropriate exit value on error
 */
static int encode_base64(const char* raw, size_t length, char** base64)
{
  size_t ptr, ptr64, out_length = ((length + 2) / 3) * 4 + 2;
  char* buf = malloc(out_length * sizeof(char));
  
  if (*base64 = buf, buf == NULL)
    return perror(execname), 2;
  
  for (ptr = ptr64 = 0; ptr < length; ptr64 += 4)
    {
      uint8_t a = (uint8_t)(ptr < length ? raw[ptr++] : 0);
      uint8_t b = (uint8_t)(ptr < length ? raw[ptr++] : 0);
      uint8_t c = (uint8_t)(ptr < length ? raw[ptr++] : 0);
      
      uint32_t abc = ((uint32_t)a << 16) | ((uint32_t)b << 8) | ((uint32_t)c << 0);
      
      buf[ptr64 | 0] = BASE64[(abc >> (3 * 6)) & 63];
      buf[ptr64 | 1] = BASE64[(abc >> (2 * 6)) & 63];
      buf[ptr64 | 2] = BASE64[(abc >> (1 * 6)) & 63];
      buf[ptr64 | 3] = BASE64[(abc >> (0 * 6)) & 63];
    }
  if (length % 3 == 1)  buf[ptr64++] = BASE64[64];
  if (length % 3 == 2)  buf[ptr64++] = BASE64[65];
  buf[ptr64++] = '\0';
  
  return 0;
}


/**
 * Here we go!
 * 
 * @param   argc  The number of command line argumnets
 * @param   argv  Command line argumnets
 * @return        Zero on success, 1 on user error, 2 on system error
 */
int main(int argc, char* argv[])
{
  int r, verbose = 0, clear_mode = 0;
  libkeccak_generalised_spec_t gspec;
  libkeccak_spec_t spec;
  long squeezes = DEFAULT_SQUEEZES, bump_level = 0;
  char* site = NULL;
  char* passphrase = NULL;
  char* raw_password = NULL;
  char* base64 = NULL;
  
  libkeccak_generalised_spec_initialise(&gspec);
  execname = *argv;
  
  t (parse_cmdline(argc, argv, &gspec, &squeezes, &bump_level, &clear_mode, &verbose));
  t (make_spec(&gspec, &spec));
  if (squeezes <= 0)
    {
      r = USER_ERROR("the squeeze count most be positive");
      goto fail;
    }
  
  squeezes += bump_level * BUMP_LEVEL_MULTIPLIER;
  
  if (verbose)
    {
      fprintf(stderr,  "bump level: %li\n", bump_level);
      fprintf(stderr,        "rate: %li\n", gspec.bitrate);
      fprintf(stderr,    "capacity: %li\n", gspec.capacity);
      fprintf(stderr, "output size: %li\n", gspec.output);
      fprintf(stderr,  "state size: %li\n", gspec.state_size);
      fprintf(stderr,   "word size: %li\n", gspec.word_size);
      fprintf(stderr, "squeezes after bump level: %li\n", squeezes);
      fprintf(stderr, "squeezes before bump level: %li\n",
	      squeezes - bump_level * BUMP_LEVEL_MULTIPLIER);
    }
  
  t (get_site(&site));
  t (get_master_passphrase(&passphrase));
  t (hash_master_passphrase(passphrase));
  
  t (calculate_raw_password(&spec, squeezes, passphrase, site, &raw_password));
  passphrase_wipe(passphrase, strlen(passphrase));
  xfree(passphrase);
  xfree(site);
  
  t (encode_base64(raw_password, (size_t)(spec.output / 8), &base64));
  xfree(raw_password);
  
  if (verbose)
    {
      fprintf(stderr, "password length before base64: %li\n", spec.output / 8);
      fprintf(stderr, "password length after base64: %li\n", strlen(base64));
    }
  
  if      (clear_mode > 1)  printf("%s", base64);
  else if (clear_mode)      printf("%s\n", base64);
  else                      printf("\033[00m>\033[08;30;40m%s\033[00m<\n", base64);
  
  free(base64);
  return 0;
  
 fail:
  if (passphrase)
    passphrase_wipe(passphrase, strlen(passphrase));
  free(passphrase);
  free(site);
  free(raw_password);
  free(base64);
  return r < 0 ? 0 : r;
}

