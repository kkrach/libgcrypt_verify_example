/*
 * Cryptography functions
 *
 * WORK92107
 *
 * Copyright (C) 2015 WORK Microwave GmbH
 *
 * Author: Karl Krach <karl.krach@work-microwave.com>
 */

#include <gcrypt.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


static int crypt_initialized = 0;

/** Extracts the content from a GPG signed file
  * @path    path to file
  * @content pointer to memory to write content to
  * @size    size of memory
  */
int crypt_extract_signed_content(const char* path, const char** content, int size) {
  gcry_error_t err;
  if (!crypt_initialized) {
    crypt_initialized = 1;


    const char * output = gcry_check_version(GCRYPT_VERSION);
    if (output) printf( "gcry_check_version=%s\n", output );
    err = gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    printf( "err=%d\n", err );


  }

  gcry_error_t gcry_pk_verify(gcry_sexp_t sig, gcry_sexp_t data, gcry_sexp_t pkey );


  return 0;
}

static void
show_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = gcry_xmalloc (size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}



typedef struct context
{
  gcry_sexp_t key_secret;
  gcry_sexp_t key_public;
  gcry_sexp_t data;
  gcry_sexp_t data_encrypted;
  gcry_sexp_t data_signed;
} *context_t;

static int
work_verify (context_t context, unsigned int final)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  int ret = 1;

  if (!context->data_signed)
    return 0;

  err = gcry_pk_verify (context->data_signed,
                        context->data,
                        context->key_public);
  if (err)
    {
      show_sexp ("data_signed:\n", context->data_signed);
      show_sexp ("data:\n", context->data);
      printf("pk_verify failed: %s\n", gpg_strerror (err));
      exit( 2 );
      ret = 0;
    }
  else if (final)
    {
      gcry_sexp_release (context->data_signed);
      context->data_signed = NULL;
    }

  return ret;
}

static void *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  struct stat st;
  char *buf;
  size_t buflen;

  fp = fopen (fname, "rb");
  if (!fp)
    {
      printf("ERROR: can't open `%s': %s\n", fname, strerror (errno));
      return NULL;
    }

  if (fstat (fileno(fp), &st))
    {
      printf ("ERROR: can't stat `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = gcry_xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      printf("error reading `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      gcry_free (buf);
      return NULL;
    }
  fclose (fp);

  if (r_length)
    *r_length = buflen;
  return buf;
}

#include <assert.h>

static void
context_init (context_t context, gcry_sexp_t key_secret, gcry_sexp_t key_public)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int key_size = 0;
  gcry_mpi_t data = NULL;
  gcry_sexp_t data_sexp = NULL;

  key_size = gcry_pk_get_nbits (key_secret);
  assert (key_size);

  data = gcry_mpi_new (key_size);
  assert (data);

  gcry_mpi_randomize (data, key_size, GCRY_STRONG_RANDOM);
  gcry_mpi_clear_bit (data, key_size - 1);
  err = gcry_sexp_build (&data_sexp, NULL, "(data (flags raw) (value %m))", data);
  assert (! err);
  gcry_mpi_release (data);

  context->key_secret = key_secret;
  context->key_public = key_public;
  context->data = data_sexp;
  context->data_encrypted = NULL;
  context->data_signed = NULL;
}

static void
context_destroy (context_t context)
{
  gcry_sexp_release (context->key_secret);
  gcry_sexp_release (context->key_public);
  gcry_sexp_release (context->data);
}

static int
work_sign (context_t context, unsigned int final)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t data_signed = NULL;
  int ret = 1;

  err = gcry_pk_sign (&data_signed, context->data, context->key_secret);
  if (gpg_err_code (err) == GPG_ERR_NOT_IMPLEMENTED)
    {
      err = GPG_ERR_NO_ERROR;
      ret = 0;
    }
  else if (err)
    {
      printf("pk_sign failed: %s\n", gpg_strerror (err));
      exit( 5 );
      ret = 0;
    }
  else
    {
      if (final)
	context->data_signed = data_signed;
      else
	gcry_sexp_release (data_signed);
    }

  return ret;
}


static int benchmark (context_t context)
{
  unsigned int loop = 2;
  unsigned int i = 0;
  int ret = 0;

  for (i = 0; i < loop; i++)
  {
    ret = work_sign(context, (i + 1) == loop);
    printf( "SIGN returned %d\n", ret );
    if (! ret) break;
  }
  for (i = 0; i < loop; i++)
  {
    ret = work_verify(context, (i + 1) == loop);
    printf( "VERIFY returned %d\n", ret );
    if (! ret) break;
  }
  return ret;
}


static void
process_key_pair_file (const char *key_pair_file)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  void *key_pair_buffer = NULL;
  gcry_sexp_t key_pair_sexp = NULL;
  gcry_sexp_t key_secret_sexp = NULL;
  gcry_sexp_t key_public_sexp = NULL;
  struct context context = { NULL };
  size_t file_length;

  key_pair_buffer = read_file (key_pair_file, &file_length);
  if (!key_pair_buffer) {
    printf("ERROR: failed to open `%s'\n", key_pair_file);
    exit( 4 );
  }

  err = gcry_sexp_sscan (&key_pair_sexp, NULL,
			 key_pair_buffer, file_length);
  if (err) {
    printf ("gcry_sexp_sscan failed\n");
    exit( 4 );
  }

  key_secret_sexp = gcry_sexp_find_token (key_pair_sexp, "private-key", 0);
  assert (key_secret_sexp);
  key_public_sexp = gcry_sexp_find_token (key_pair_sexp, "public-key", 0);
  assert (key_public_sexp);

  gcry_sexp_release (key_pair_sexp);

  context_init (&context, key_secret_sexp, key_public_sexp);

  printf ("Key file: %s\n", key_pair_file);
  benchmark (&context);
  printf ("\n");

  context_destroy (&context);
  gcry_free (key_pair_buffer);
}

#include <ctype.h>
static void generate_key (const char *algorithm, const char *key_size)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  size_t key_pair_buffer_size = 0;
  char *key_pair_buffer = NULL;
  gcry_sexp_t key_spec = NULL;
  gcry_sexp_t key_pair = NULL;

  printf ("generate_key... 1\n"); fflush(stdout);
  if (isdigit ((unsigned int)*key_size))
    err = gcry_sexp_build (&key_spec, NULL,
                           "(genkey (%s (nbits %s)))",
                           algorithm, key_size);
  else
    err = gcry_sexp_build (&key_spec, NULL,
                           "(genkey (%s (curve %s)))",
                           algorithm, key_size);
  printf ("generate_key... 2\n"); fflush(stdout);
  if (err) {
    printf ("sexp_build failed: %s\n", gpg_strerror (err));
    exit(2);
  }

  printf ("generate_key... 3\n"); fflush(stdout);
  err = gcry_pk_genkey (&key_pair, key_spec);
  printf ("generate_key... 3a\n"); fflush(stdout);
  if (err)
  {
    show_sexp ("request:\n", key_spec);
    printf ("pk_genkey failed: %s\n", gpg_strerror (err));
    exit( 3 );
  }

  printf ("generate_key... 4\n"); fflush(stdout);
  key_pair_buffer_size = gcry_sexp_sprint (key_pair, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  key_pair_buffer = gcry_xmalloc (key_pair_buffer_size);

  printf ("generate_key... 5\n"); fflush(stdout);
  gcry_sexp_sprint (key_pair, GCRYSEXP_FMT_ADVANCED, key_pair_buffer, key_pair_buffer_size);

  printf ("generate_key... 6\n"); fflush(stdout);
  printf ("%.*s", (int)key_pair_buffer_size, key_pair_buffer);
  gcry_free (key_pair_buffer);
}

int main (int argc, char **argv)
{
  printf( "starting crypt...\n" );
  int verbose=0, debug=0;
  int genkey_mode = 0;
  int fips_mode = 0;

  genkey_mode = 1;  // --genkey
  //fips_mode = 1;    // --fips

  printf ("A\n"); fflush(stdout);

  gcry_control (GCRYCTL_SET_VERBOSITY, (int)verbose);

  if (fips_mode) gcry_control (GCRYCTL_FORCE_FIPS_MODE, 0);

  printf ("b\n"); fflush(stdout);
  gcry_control (GCRYCTL_DISABLE_SECMEM);
  if (!gcry_check_version (GCRYPT_VERSION)) {
    fprintf (stderr, "ERROR: version mismatch\n");
    exit (1);
  }
  printf ("c\n"); fflush(stdout);
  if (genkey_mode) {
      /* No valuable keys are create, so we can speed up our RNG. */
      gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  }
  printf ("d\n"); fflush(stdout);
  if (debug) gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

#if 0
  printf ("starting generate_key...\n"); fflush(stdout);
  generate_key("rsa", "4096");
#else
  printf( "process_key_pair_file...\n" ); fflush(stdout);
  process_key_pair_file ("keypair.txt");
#endif
  printf( "done...\n" );
  return 0;
}


















