/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "streams/openssl.h"

#ifdef GIT_OPENSSL

#include <ctype.h>

#include "runtime.h"
#include "settings.h"
#include "posix.h"
#include "stream.h"
#include "streams/socket.h"
#include "netops.h"
#include "git2/transport.h"
#include "git2/sys/openssl.h"

#ifndef GIT_WIN32
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

SSL_CTX *git__ssl_ctx;

#define GIT_SSL_DEFAULT_CIPHERS "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"

#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L) || \
     (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
# define OPENSSL_LEGACY_API
#endif


/*
 * We can dlopen openssl when requested, however we do not support the
 * "legacy api" so the current build platform must be reasonably new.
 */
#ifdef GIT_OPENSSL_DYNAMIC

# ifdef OPENSSL_LEGACY_API
#  error dynamically loaded openssl requires a modern openssl API
# endif

# include <dlfcn.h>

void *openssl_handle;

const unsigned char *(*_ASN1_STRING_get0_data)(const ASN1_STRING *x);
int (*_ASN1_STRING_length)(const ASN1_STRING *x);
int (*_ASN1_STRING_to_UTF8)(unsigned char **out, const ASN1_STRING *in);
int (*_ASN1_STRING_type)(const ASN1_STRING *x);

void *(*_BIO_get_data)(BIO *a);
int (*_BIO_get_new_index)(void);
void (*_BIO_meth_free)(BIO_METHOD *biom);
BIO_METHOD *(*_BIO_meth_new)(int type, const char *name);
int (*_BIO_meth_set_create)(BIO_METHOD *biom, int (*create) (BIO *));
int (*_BIO_meth_set_ctrl)(BIO_METHOD *biom, long (*ctrl) (BIO *, int, long, void *));
int (*_BIO_meth_set_destroy)(BIO_METHOD *biom, int (*destroy) (BIO *));
int (*_BIO_meth_set_gets)(BIO_METHOD *biom, int (*gets) (BIO *, char *, int));
int (*_BIO_meth_set_puts)(BIO_METHOD *biom, int (*puts) (BIO *, const char *));
int (*_BIO_meth_set_read)(BIO_METHOD *biom, int (*read) (BIO *, char *, int));
int (*_BIO_meth_set_write)(BIO_METHOD *biom, int (*write) (BIO *, const char *, int));
BIO *(*_BIO_new)(const BIO_METHOD *type);
void (*_BIO_set_data)(BIO *a, void *ptr);
void (*_BIO_set_init)(BIO *a, int init);

void (*_CRYPTO_free)(void *ptr, const char *file, int line);
void *(*_CRYPTO_malloc)(size_t num, const char *file, int line);

char *(*_ERR_error_string)(unsigned long e, char *buf);
void (*_ERR_error_string_n)(unsigned long e, char *buf, size_t len);
unsigned long (*_ERR_get_error)(void);

# define _sk_GENERAL_NAME_num(sk) _OPENSSL_sk_num((const OPENSSL_STACK *)sk)
# define _sk_GENERAL_NAME_value(sk, idx) _OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx)
# define _GENERAL_NAMES_free(sk) _OPENSSL_sk_free((OPENSSL_STACK *)sk);

int (*_OPENSSL_init_ssl)(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
int (*_OPENSSL_sk_num)(const OPENSSL_STACK *sk);
void *(*_OPENSSL_sk_value)(const OPENSSL_STACK *sk, int i);
void (*_OPENSSL_sk_free)(OPENSSL_STACK *sk);

# define _OPENSSL_malloc(num) _CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
# define _OPENSSL_free(addr) _CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)

int (*_SSL_connect)(SSL *ssl);
long (*_SSL_ctrl)(SSL *ssl, int cmd, long arg, void *parg);
void (*_SSL_free)(SSL *ssl);
int (*_SSL_get_error)(SSL *ssl, int ret);
X509 *(*_SSL_get_peer_certificate)(const SSL *ssl);
long (*_SSL_get_verify_result)(const SSL *ssl);
SSL *(*_SSL_new)(SSL_CTX *ctx);
int (*_SSL_read)(SSL *ssl, const void *buf, int num);
void (*_SSL_set_bio)(SSL *ssl, BIO *rbio, BIO *wbio);
int (*_SSL_shutdown)(SSL *ssl);
int (*_SSL_write)(SSL *ssl, const void *buf, int num);

long (*_SSL_CTX_ctrl)(SSL_CTX *ctx, int cmd, long larg, void *parg);
void (*_SSL_CTX_free)(SSL_CTX *ctx);
SSL_CTX *(*_SSL_CTX_new)(const SSL_METHOD *method);
int (*_SSL_CTX_set_cipher_list)(SSL_CTX *ctx, const char *str);
int (*_SSL_CTX_set_default_verify_paths)(SSL_CTX *ctx);
long (*_SSL_CTX_set_options)(SSL_CTX *ctx, long options);
void (*_SSL_CTX_set_verify)(SSL_CTX *ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX *));
int (*_SSL_CTX_load_verify_locations)(SSL_CTX *ctx, const char *CAfile, const char *CApath);

# define _SSL_CTX_set_mode(ctx, mode) _SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, mode, NULL)

# define _SSLv23_method _TLS_method

const SSL_METHOD *(*_TLS_method)(void);

ASN1_STRING *(*_X509_NAME_ENTRY_get_data)(const X509_NAME_ENTRY *ne);
X509_NAME_ENTRY *(*_X509_NAME_get_entry)(X509_NAME *name, int loc);
int (*_X509_NAME_get_index_by_NID)(X509_NAME *name, int nid, int lastpos);
void (*_X509_free)(X509 *a);
void *(*_X509_get_ext_d2i)(const X509 *x, int nid, int *crit, int *idx);
X509_NAME *(*_X509_get_subject_name)(const X509 *x);

int (*_i2d_X509)(X509 *a, unsigned char **ppout);

GIT_INLINE(void *) openssl_sym(int *err, const char *name)
{
	void *symbol;

	/* if we've seen an err, noop to retain it */
	if (*err)
		return NULL;

	if ((symbol = dlsym(openssl_handle, name)) == NULL) {
		const char *msg = dlerror();
		git_error_set(GIT_ERROR_SSL, "could not load ssl function '%s': %s", name, msg ? msg : "unknown error");
		*err = -1;
	}

	return symbol;
}

static int openssl_dynamic_init(void)
{
	int err = 0;

	if ((openssl_handle = dlopen("libssl.so.1.1", RTLD_NOW)) == NULL) {
		git_error_set(GIT_ERROR_SSL, "could not load ssl libraries");
		return -1;
	}

	_ASN1_STRING_get0_data = (const unsigned char *(*)(const ASN1_STRING *x))openssl_sym(&err, "ASN1_STRING_get0_data");
	_ASN1_STRING_length = (int (*)(const ASN1_STRING *))openssl_sym(&err, "ASN1_STRING_length");
	_ASN1_STRING_to_UTF8 = (int (*)(unsigned char **, const ASN1_STRING *))openssl_sym(&err, "ASN1_STRING_to_UTF8");
	_ASN1_STRING_type = (int (*)(const ASN1_STRING *))openssl_sym(&err, "ASN1_STRING_type");

	_BIO_get_data = (void *(*)(BIO *))openssl_sym(&err, "BIO_get_data");
	_BIO_get_new_index = (int (*)(void))openssl_sym(&err, "BIO_get_new_index");
	_BIO_meth_free = (void (*)(BIO_METHOD *))openssl_sym(&err, "BIO_meth_free");
	_BIO_meth_new = (BIO_METHOD *(*)(int, const char *))openssl_sym(&err, "BIO_meth_new");
	_BIO_meth_set_create = (int (*)(BIO_METHOD *, int (*)(BIO *)))openssl_sym(&err, "BIO_meth_set_create");
	_BIO_meth_set_ctrl = (int (*)(BIO_METHOD *, long (*)(BIO *, int, long, void *)))openssl_sym(&err, "BIO_meth_set_ctrl");
	_BIO_meth_set_destroy = (int (*)(BIO_METHOD *, int (*)(BIO *)))openssl_sym(&err, "BIO_meth_set_destroy");
	_BIO_meth_set_gets = (int (*)(BIO_METHOD *, int (*)(BIO *, char *, int)))openssl_sym(&err, "BIO_meth_set_gets");
	_BIO_meth_set_puts = (int (*)(BIO_METHOD *, int (*)(BIO *, const char *)))openssl_sym(&err, "BIO_meth_set_puts");
	_BIO_meth_set_read = (int (*)(BIO_METHOD *, int (*)(BIO *, char *, int)))openssl_sym(&err, "BIO_meth_set_read");
	_BIO_meth_set_write = (int (*)(BIO_METHOD *, int (*)(BIO *, const char *, int)))openssl_sym(&err, "BIO_meth_set_write");
	_BIO_new = (BIO *(*)(const BIO_METHOD *))openssl_sym(&err, "BIO_new");
	_BIO_set_data = (void (*)(BIO *a, void *))openssl_sym(&err, "BIO_set_data");
	_BIO_set_init = (void (*)(BIO *a, int))openssl_sym(&err, "BIO_set_init");

	_CRYPTO_free = (void (*)(void *, const char *, int))openssl_sym(&err, "CRYPTO_free");
	_CRYPTO_malloc = (void *(*)(size_t, const char *, int))openssl_sym(&err, "CRYPTO_malloc");

	_ERR_error_string = (char *(*)(unsigned long, char *))openssl_sym(&err, "ERR_error_string");
	_ERR_error_string_n = (void (*)(unsigned long, char *, size_t))openssl_sym(&err, "ERR_error_string_n");
	_ERR_get_error = (unsigned long (*)(void))openssl_sym(&err, "ERR_get_error");

	_OPENSSL_init_ssl = (int (*)(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings))openssl_sym(&err, "OPENSSL_init_ssl");
	_OPENSSL_sk_num = (int (*)(const OPENSSL_STACK *))openssl_sym(&err, "OPENSSL_sk_num");
	_OPENSSL_sk_value = (void *(*)(const OPENSSL_STACK *sk, int i))openssl_sym(&err, "OPENSSL_sk_value");
	_OPENSSL_sk_free = (void (*)(OPENSSL_STACK *))openssl_sym(&err, "OPENSSL_sk_free");

	_SSL_connect = (int (*)(SSL *))openssl_sym(&err, "SSL_connect");
	_SSL_ctrl = (long (*)(SSL *, int, long, void *))openssl_sym(&err, "SSL_ctrl");
	_SSL_get_peer_certificate = (X509 *(*)(const SSL *))openssl_sym(&err, "SSL_get_peer_certificate");
	_SSL_free = (void (*)(SSL *))openssl_sym(&err, "SSL_free");
	_SSL_get_error = (int (*)(SSL *, int))openssl_sym(&err, "SSL_get_error");
	_SSL_get_verify_result = (long (*)(const SSL *ssl))openssl_sym(&err, "SSL_get_verify_result");
	_SSL_new = (SSL *(*)(SSL_CTX *))openssl_sym(&err, "SSL_new");
	_SSL_read = (int (*)(SSL *, const void *, int))openssl_sym(&err, "SSL_read");
	_SSL_set_bio = (void (*)(SSL *, BIO *, BIO *))openssl_sym(&err, "SSL_set_bio");
	_SSL_shutdown = (int (*)(SSL *ssl))openssl_sym(&err, "SSL_shutdown");
	_SSL_write = (int (*)(SSL *, const void *, int))openssl_sym(&err, "SSL_write");

	_SSL_CTX_ctrl = (long (*)(SSL_CTX *, int, long, void *))openssl_sym(&err, "SSL_CTX_ctrl");
	_SSL_CTX_free = (void (*)(SSL_CTX *))openssl_sym(&err, "SSL_CTX_free");
	_SSL_CTX_new = (SSL_CTX *(*)(const SSL_METHOD *))openssl_sym(&err, "SSL_CTX_new");
	_SSL_CTX_set_cipher_list = (int (*)(SSL_CTX *, const char *))openssl_sym(&err, "SSL_CTX_set_cipher_list");
	_SSL_CTX_set_default_verify_paths = (int (*)(SSL_CTX *ctx))openssl_sym(&err, "SSL_CTX_set_default_verify_paths");
	_SSL_CTX_set_options = (long (*)(SSL_CTX *, long))openssl_sym(&err, "SSL_CTX_set_options");
	_SSL_CTX_set_verify = (void (*)(SSL_CTX *, int, int (*)(int, X509_STORE_CTX *)))openssl_sym(&err, "SSL_CTX_set_verify");
	_SSL_CTX_load_verify_locations = (int (*)(SSL_CTX *, const char *, const char *))openssl_sym(&err, "SSL_CTX_load_verify_locations");

	_TLS_method = (const SSL_METHOD *(*)(void))openssl_sym(&err, "TLS_method");

	_X509_NAME_ENTRY_get_data = (ASN1_STRING *(*)(const X509_NAME_ENTRY *))openssl_sym(&err, "X509_NAME_ENTRY_get_data");
	_X509_NAME_get_entry = (X509_NAME_ENTRY *(*)(X509_NAME *, int))openssl_sym(&err, "X509_NAME_get_entry");
	_X509_NAME_get_index_by_NID = (int (*)(X509_NAME *, int, int))openssl_sym(&err, "X509_NAME_get_index_by_NID");
	_X509_free = (void (*)(X509 *))openssl_sym(&err, "X509_free");
	_X509_get_ext_d2i = (void *(*)(const X509 *x, int nid, int *crit, int *idx))openssl_sym(&err, "X509_get_ext_d2i");
	_X509_get_subject_name = (X509_NAME *(*)(const X509 *))openssl_sym(&err, "X509_get_subject_name");

	_i2d_X509 = (int (*)(X509 *a, unsigned char **ppout))openssl_sym(&err, "i2d_X509");

	return err;
}

#else /* GIT_OPENSSL_DYNAMIC */

# define _ASN1_STRING_get0_data ASN1_STRING_get0_data
# define _ASN1_STRING_length ASN1_STRING_length
# define _ASN1_STRING_to_UTF8 ASN1_STRING_to_UTF8
# define _ASN1_STRING_type ASN1_STRING_type
# define _BIO_get_data BIO_get_data
# define _BIO_get_new_index BIO_get_new_index
# define _BIO_meth_free BIO_meth_free
# define _BIO_meth_new BIO_meth_new
# define _BIO_meth_set_create BIO_meth_set_create
# define _BIO_meth_set_ctrl BIO_meth_set_ctrl
# define _BIO_meth_set_destroy BIO_meth_set_destroy
# define _BIO_meth_set_gets BIO_meth_set_gets
# define _BIO_meth_set_puts BIO_meth_set_puts
# define _BIO_meth_set_read BIO_meth_set_read
# define _BIO_meth_set_write BIO_meth_set_write
# define _BIO_new BIO_new
# define _BIO_set_data BIO_set_data
# define _BIO_set_init BIO_set_init
# define _ERR_error_string ERR_error_string
# define _ERR_error_string_n ERR_error_string_n
# define _ERR_get_error ERR_get_error
# define _GENERAL_NAMES_free GENERAL_NAMES_free
# define _i2d_X509 i2d_X509
# define _OPENSSL_free OPENSSL_free
# define _OPENSSL_init_ssl OPENSSL_init_ssl
# define _OPENSSL_malloc OPENSSL_malloc
# define _sk_GENERAL_NAME_num sk_GENERAL_NAME_num
# define _sk_GENERAL_NAME_value sk_GENERAL_NAME_value
# define _SSL_ctrl SSL_ctrl
# define _SSL_new SSL_new
# define _SSL_connect SSL_connect
# define _SSL_set_bio SSL_set_bio
# define _SSL_read SSL_read
# define _SSL_write SSL_write
# define _SSL_get_error SSL_get_error
# define _SSL_free SSL_free
# define _SSL_get_peer_certificate SSL_get_peer_certificate
# define _SSL_get_verify_result SSL_get_verify_result
# define _SSL_shutdown SSL_shutdown
# define _SSL_CTX_free SSL_CTX_free
# define _SSL_CTX_load_verify_locations SSL_CTX_load_verify_locations
# define _SSL_CTX_new SSL_CTX_new
# define _SSL_CTX_set_cipher_list SSL_CTX_set_cipher_list
# define _SSL_CTX_set_default_verify_paths SSL_CTX_set_default_verify_paths
# define _SSL_CTX_set_mode SSL_CTX_set_mode
# define _SSL_CTX_set_options SSL_CTX_set_options
# define _SSL_CTX_set_verify SSL_CTX_set_verify
# define _SSLv23_method SSLv23_method
# define _X509_free X509_free
# define _X509_get_ext_d2i X509_get_ext_d2i
# define _X509_get_subject_name X509_get_subject_name
# define _X509_NAME_ENTRY_get_data X509_NAME_ENTRY_get_data
# define _X509_NAME_get_entry X509_NAME_get_entry
# define _X509_NAME_get_index_by_NID X509_NAME_get_index_by_NID

#endif /* GIT_OPENSSL_DYNAMIC */


/*
 * OpenSSL 1.1 made BIO opaque so we have to use functions to interact with it
 * which do not exist in previous versions. We define these inline functions so
 * we can program against the interface instead of littering the implementation
 * with ifdefs. We do the same for OPENSSL_init_ssl.
 */
#if defined(OPENSSL_LEGACY_API)
static int _OPENSSL_init_ssl(int opts, void *settings)
{
	GIT_UNUSED(opts);
	GIT_UNUSED(settings);
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	return 0;
}

static BIO_METHOD* _BIO_meth_new(int type, const char *name)
{
	BIO_METHOD *meth = git__calloc(1, sizeof(BIO_METHOD));
	if (!meth) {
		return NULL;
	}

	meth->type = type;
	meth->name = name;

	return meth;
}

static void _BIO_meth_free(BIO_METHOD *biom)
{
	git__free(biom);
}

static int _BIO_meth_set_write(BIO_METHOD *biom, int (*write) (BIO *, const char *, int))
{
	biom->bwrite = write;
	return 1;
}

static int _BIO_meth_set_read(BIO_METHOD *biom, int (*read) (BIO *, char *, int))
{
	biom->bread = read;
	return 1;
}

static int _BIO_meth_set_puts(BIO_METHOD *biom, int (*puts) (BIO *, const char *))
{
	biom->bputs = puts;
	return 1;
}

static int _BIO_meth_set_gets(BIO_METHOD *biom, int (*gets) (BIO *, char *, int))

{
	biom->bgets = gets;
	return 1;
}

static int _BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl) (BIO *, int, long, void *))
{
	biom->ctrl = ctrl;
	return 1;
}

static int _BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *))
{
	biom->create = create;
	return 1;
}

static int _BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *))
{
	biom->destroy = destroy;
	return 1;
}

static int _BIO_get_new_index(void)
{
	/* This exists as of 1.1 so before we'd just have 0 */
	return 0;
}

static void _BIO_set_init(BIO *b, int init)
{
	b->init = init;
}

static void _BIO_set_data(BIO *a, void *ptr)
{
	a->ptr = ptr;
}

static void *_BIO_get_data(BIO *a)
{
	return a->ptr;
}

static const unsigned char *_ASN1_STRING_get0_data(const ASN1_STRING *x)
{
	return ASN1_STRING_data((ASN1_STRING *)x);
}

# if defined(GIT_THREADS)
static git_mutex *openssl_locks;

static void openssl_locking_function(
	int mode, int n, const char *file, int line)
{
	int lock;

	GIT_UNUSED(file);
	GIT_UNUSED(line);

	lock = mode & CRYPTO_LOCK;

	if (lock) {
		(void)git_mutex_lock(&openssl_locks[n]);
	} else {
		git_mutex_unlock(&openssl_locks[n]);
	}
}

static void shutdown_ssl_locking(void)
{
	int num_locks, i;

	num_locks = CRYPTO_num_locks();
	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < num_locks; ++i)
		git_mutex_free(&openssl_locks[i]);
	git__free(openssl_locks);
}
# endif /* GIT_THREADS */
#endif /* OPENSSL_LEGACY_API */

static BIO_METHOD *git_stream_bio_method;
static int init_bio_method(void);

/**
 * This function aims to clean-up the SSL context which
 * we allocated.
 */
static void shutdown_ssl(void)
{
	if (git_stream_bio_method) {
		_BIO_meth_free(git_stream_bio_method);
		git_stream_bio_method = NULL;
	}

	if (git__ssl_ctx) {
		_SSL_CTX_free(git__ssl_ctx);
		git__ssl_ctx = NULL;
	}
}

#ifdef VALGRIND
#ifdef OPENSSL_LEGACY_API
static void *git_openssl_malloc(size_t bytes)
{
	return git__calloc(1, bytes);
}

static void *git_openssl_realloc(void *mem, size_t size)
{
	return git__realloc(mem, size);
}

static void git_openssl_free(void *mem)
{
	return git__free(mem);
}
#else
static void *git_openssl_malloc(size_t bytes, const char *file, int line)
{
	GIT_UNUSED(file);
	GIT_UNUSED(line);
	return git__calloc(1, bytes);
}

static void *git_openssl_realloc(void *mem, size_t size, const char *file, int line)
{
	GIT_UNUSED(file);
	GIT_UNUSED(line);
	return git__realloc(mem, size);
}

static void git_openssl_free(void *mem, const char *file, int line)
{
	GIT_UNUSED(file);
	GIT_UNUSED(line);
	return git__free(mem);
}
#endif
#endif

int git_openssl_stream_global_init(void)
{
	long ssl_opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
	const char *ciphers = git_libgit2__ssl_ciphers();
#ifdef VALGRIND
	static bool allocators_initialized = false;
#endif

#ifdef GIT_OPENSSL_DYNAMIC
	if (openssl_dynamic_init() < 0)
		return -1;
#endif

	/* Older OpenSSL and MacOS OpenSSL doesn't have this */
#ifdef SSL_OP_NO_COMPRESSION
	ssl_opts |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef VALGRIND
	/* Swap in our own allocator functions that initialize allocated memory */
	if (!allocators_initialized &&
	    CRYPTO_set_mem_functions(git_openssl_malloc,
				     git_openssl_realloc,
				     git_openssl_free) != 1)
		goto error;
	allocators_initialized = true;
#endif

	_OPENSSL_init_ssl(0, NULL);

	/*
	 * Load SSLv{2,3} and TLSv1 so that we can talk with servers
	 * which use the SSL hellos, which are often used for
	 * compatibility. We then disable SSL so we only allow OpenSSL
	 * to speak TLSv1 to perform the encryption itself.
	 */
	if (!(git__ssl_ctx = _SSL_CTX_new(_SSLv23_method())))
		goto error;

	_SSL_CTX_set_options(git__ssl_ctx, ssl_opts);
	_SSL_CTX_set_mode(git__ssl_ctx, SSL_MODE_AUTO_RETRY);
	_SSL_CTX_set_verify(git__ssl_ctx, SSL_VERIFY_NONE, NULL);
	if (!_SSL_CTX_set_default_verify_paths(git__ssl_ctx))
		goto error;

	if (!ciphers)
		ciphers = GIT_SSL_DEFAULT_CIPHERS;

	if(!_SSL_CTX_set_cipher_list(git__ssl_ctx, ciphers))
		goto error;

	if (init_bio_method() < 0)
		goto error;

	return git_runtime_shutdown_register(shutdown_ssl);

error:
	git_error_set(GIT_ERROR_NET, "could not initialize openssl: %s",
		_ERR_error_string(_ERR_get_error(), NULL));
	_SSL_CTX_free(git__ssl_ctx);
	git__ssl_ctx = NULL;
	return -1;
}

#if defined(GIT_THREADS) && defined(OPENSSL_LEGACY_API)
static void threadid_cb(CRYPTO_THREADID *threadid)
{
	GIT_UNUSED(threadid);
	CRYPTO_THREADID_set_numeric(threadid, git_thread_currentid());
}
#endif

int git_openssl_set_locking(void)
{
#if defined(GIT_THREADS) && defined(OPENSSL_LEGACY_API)
	int num_locks, i;

	CRYPTO_THREADID_set_callback(threadid_cb);

	num_locks = CRYPTO_num_locks();
	openssl_locks = git__calloc(num_locks, sizeof(git_mutex));
	GIT_ERROR_CHECK_ALLOC(openssl_locks);

	for (i = 0; i < num_locks; i++) {
		if (git_mutex_init(&openssl_locks[i]) != 0) {
			git_error_set(GIT_ERROR_SSL, "failed to initialize openssl locks");
			return -1;
		}
	}

	CRYPTO_set_locking_callback(openssl_locking_function);
	return git_runtime_shutdown_register(shutdown_ssl_locking);

#elif !defined(OPENSSL_LEGACY_API)
	return 0;
#else
	git_error_set(GIT_ERROR_THREAD, "libgit2 was not built with threads");
	return -1;
#endif
}


static int bio_create(BIO *b)
{
	_BIO_set_init(b, 1);
	_BIO_set_data(b, NULL);

	return 1;
}

static int bio_destroy(BIO *b)
{
	if (!b)
		return 0;

	_BIO_set_data(b, NULL);

	return 1;
}

static int bio_read(BIO *b, char *buf, int len)
{
	git_stream *io = (git_stream *) _BIO_get_data(b);

	return (int) git_stream_read(io, buf, len);
}

static int bio_write(BIO *b, const char *buf, int len)
{
	git_stream *io = (git_stream *) _BIO_get_data(b);
	return (int) git_stream_write(io, buf, len, 0);
}

static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	GIT_UNUSED(b);
	GIT_UNUSED(num);
	GIT_UNUSED(ptr);

	if (cmd == BIO_CTRL_FLUSH)
		return 1;

	return 0;
}

static int bio_gets(BIO *b, char *buf, int len)
{
	GIT_UNUSED(b);
	GIT_UNUSED(buf);
	GIT_UNUSED(len);
	return -1;
}

static int bio_puts(BIO *b, const char *str)
{
	return bio_write(b, str, strlen(str));
}

static int init_bio_method(void)
{
	/* Set up the BIO_METHOD we use for wrapping our own stream implementations */
	git_stream_bio_method = _BIO_meth_new(BIO_TYPE_SOURCE_SINK | _BIO_get_new_index(), "git_stream");
	GIT_ERROR_CHECK_ALLOC(git_stream_bio_method);

	_BIO_meth_set_write(git_stream_bio_method, bio_write);
	_BIO_meth_set_read(git_stream_bio_method, bio_read);
	_BIO_meth_set_puts(git_stream_bio_method, bio_puts);
	_BIO_meth_set_gets(git_stream_bio_method, bio_gets);
	_BIO_meth_set_ctrl(git_stream_bio_method, bio_ctrl);
	_BIO_meth_set_create(git_stream_bio_method, bio_create);
	_BIO_meth_set_destroy(git_stream_bio_method, bio_destroy);

	return 0;
}

static int ssl_set_error(SSL *ssl, int error)
{
	int err;
	unsigned long e;

	err = _SSL_get_error(ssl, error);

	GIT_ASSERT(err != SSL_ERROR_WANT_READ);
	GIT_ASSERT(err != SSL_ERROR_WANT_WRITE);

	switch (err) {
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
		git_error_set(GIT_ERROR_SSL, "SSL error: connection failure");
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		git_error_set(GIT_ERROR_SSL, "SSL error: x509 error");
		break;
	case SSL_ERROR_SYSCALL:
		e = _ERR_get_error();
		if (e > 0) {
			char errmsg[256];
			_ERR_error_string_n(e, errmsg, sizeof(errmsg));
			git_error_set(GIT_ERROR_NET, "SSL error: %s", errmsg);
			break;
		} else if (error < 0) {
			git_error_set(GIT_ERROR_OS, "SSL error: syscall failure");
			break;
		}
		git_error_set(GIT_ERROR_SSL, "SSL error: received early EOF");
		return GIT_EEOF;
		break;
	case SSL_ERROR_SSL:
	{
		char errmsg[256];
		e = _ERR_get_error();
		_ERR_error_string_n(e, errmsg, sizeof(errmsg));
		git_error_set(GIT_ERROR_SSL, "SSL error: %s", errmsg);
		break;
	}
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
	default:
		git_error_set(GIT_ERROR_SSL, "SSL error: unknown error");
		break;
	}
	return -1;
}

static int ssl_teardown(SSL *ssl)
{
	int ret;

	ret = _SSL_shutdown(ssl);
	if (ret < 0)
		ret = ssl_set_error(ssl, ret);
	else
		ret = 0;

	return ret;
}

static int check_host_name(const char *name, const char *host)
{
	if (!strcasecmp(name, host))
		return 0;

	if (gitno__match_host(name, host) < 0)
		return -1;

	return 0;
}

static int verify_server_cert(SSL *ssl, const char *host)
{
	X509 *cert = NULL;
	X509_NAME *peer_name;
	ASN1_STRING *str;
	unsigned char *peer_cn = NULL;
	int matched = -1, type = GEN_DNS;
	GENERAL_NAMES *alts;
	struct in6_addr addr6;
	struct in_addr addr4;
	void *addr = NULL;
	int i = -1, j, error = 0;

	if (_SSL_get_verify_result(ssl) != X509_V_OK) {
		git_error_set(GIT_ERROR_SSL, "the SSL certificate is invalid");
		return GIT_ECERTIFICATE;
	}

	/* Try to parse the host as an IP address to see if it is */
	if (p_inet_pton(AF_INET, host, &addr4)) {
		type = GEN_IPADD;
		addr = &addr4;
	} else {
		if (p_inet_pton(AF_INET6, host, &addr6)) {
			type = GEN_IPADD;
			addr = &addr6;
		}
	}


	cert = _SSL_get_peer_certificate(ssl);
	if (!cert) {
		error = -1;
		git_error_set(GIT_ERROR_SSL, "the server did not provide a certificate");
		goto cleanup;
	}

	/* Check the alternative names */
	alts = _X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (alts) {
		int num;

		num = _sk_GENERAL_NAME_num(alts);
		for (i = 0; i < num && matched != 1; i++) {
			const GENERAL_NAME *gn = _sk_GENERAL_NAME_value(alts, i);
			const char *name = (char *) _ASN1_STRING_get0_data(gn->d.ia5);
			size_t namelen = (size_t) _ASN1_STRING_length(gn->d.ia5);

			/* Skip any names of a type we're not looking for */
			if (gn->type != type)
				continue;

			if (type == GEN_DNS) {
				/* If it contains embedded NULs, don't even try */
				if (memchr(name, '\0', namelen))
					continue;

				if (check_host_name(name, host) < 0)
					matched = 0;
				else
					matched = 1;
			} else if (type == GEN_IPADD) {
				/* Here name isn't so much a name but a binary representation of the IP */
				matched = addr && !!memcmp(name, addr, namelen);
			}
		}
	}
	_GENERAL_NAMES_free(alts);

	if (matched == 0)
		goto cert_fail_name;

	if (matched == 1) {
		goto cleanup;
	}

	/* If no alternative names are available, check the common name */
	peer_name = _X509_get_subject_name(cert);
	if (peer_name == NULL)
		goto on_error;

	if (peer_name) {
		/* Get the index of the last CN entry */
		while ((j = _X509_NAME_get_index_by_NID(peer_name, NID_commonName, i)) >= 0)
			i = j;
	}

	if (i < 0)
		goto on_error;

	str = _X509_NAME_ENTRY_get_data(_X509_NAME_get_entry(peer_name, i));
	if (str == NULL)
		goto on_error;

	/* Work around a bug in OpenSSL whereby ASN1_STRING_to_UTF8 fails if it's already in utf-8 */
	if (_ASN1_STRING_type(str) == V_ASN1_UTF8STRING) {
		int size = _ASN1_STRING_length(str);

		if (size > 0) {
			peer_cn = _OPENSSL_malloc(size + 1);
			GIT_ERROR_CHECK_ALLOC(peer_cn);
			memcpy(peer_cn, _ASN1_STRING_get0_data(str), size);
			peer_cn[size] = '\0';
		} else {
			goto cert_fail_name;
		}
	} else {
		int size = _ASN1_STRING_to_UTF8(&peer_cn, str);
		GIT_ERROR_CHECK_ALLOC(peer_cn);
		if (memchr(peer_cn, '\0', size))
			goto cert_fail_name;
	}

	if (check_host_name((char *)peer_cn, host) < 0)
		goto cert_fail_name;

	goto cleanup;

cert_fail_name:
	error = GIT_ECERTIFICATE;
	git_error_set(GIT_ERROR_SSL, "hostname does not match certificate");
	goto cleanup;

on_error:
	error = ssl_set_error(ssl, 0);
	goto cleanup;

cleanup:
	_X509_free(cert);
	_OPENSSL_free(peer_cn);
	return error;
}

typedef struct {
	git_stream parent;
	git_stream *io;
	int owned;
	bool connected;
	char *host;
	SSL *ssl;
	git_cert_x509 cert_info;
} openssl_stream;

static int openssl_connect(git_stream *stream)
{
	int ret;
	BIO *bio;
	openssl_stream *st = (openssl_stream *) stream;

	if (st->owned && (ret = git_stream_connect(st->io)) < 0)
		return ret;

	bio = _BIO_new(git_stream_bio_method);
	GIT_ERROR_CHECK_ALLOC(bio);

	_BIO_set_data(bio, st->io);
	_SSL_set_bio(st->ssl, bio, bio);

	/* specify the host in case SNI is needed */
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	_SSL_ctrl(st->ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void *)st->host);
#endif

	if ((ret = _SSL_connect(st->ssl)) <= 0)
		return ssl_set_error(st->ssl, ret);

	st->connected = true;

	return verify_server_cert(st->ssl, st->host);
}

static int openssl_certificate(git_cert **out, git_stream *stream)
{
	openssl_stream *st = (openssl_stream *) stream;
	X509 *cert = _SSL_get_peer_certificate(st->ssl);
	unsigned char *guard, *encoded_cert = NULL;
	int error, len;

	/* Retrieve the length of the certificate first */
	len = _i2d_X509(cert, NULL);
	if (len < 0) {
		git_error_set(GIT_ERROR_NET, "failed to retrieve certificate information");
		error = -1;
		goto out;
	}

	encoded_cert = git__malloc(len);
	GIT_ERROR_CHECK_ALLOC(encoded_cert);
	/* i2d_X509 makes 'guard' point to just after the data */
	guard = encoded_cert;

	len = _i2d_X509(cert, &guard);
	if (len < 0) {
		git_error_set(GIT_ERROR_NET, "failed to retrieve certificate information");
		error = -1;
		goto out;
	}

	st->cert_info.parent.cert_type = GIT_CERT_X509;
	st->cert_info.data = encoded_cert;
	st->cert_info.len = len;
	encoded_cert = NULL;

	*out = &st->cert_info.parent;
	error = 0;

out:
	git__free(encoded_cert);
	_X509_free(cert);
	return error;
}

static int openssl_set_proxy(git_stream *stream, const git_proxy_options *proxy_opts)
{
	openssl_stream *st = (openssl_stream *) stream;

	return git_stream_set_proxy(st->io, proxy_opts);
}

static ssize_t openssl_write(git_stream *stream, const char *data, size_t data_len, int flags)
{
	openssl_stream *st = (openssl_stream *) stream;
	int ret, len = min(data_len, INT_MAX);

	GIT_UNUSED(flags);

	if ((ret = _SSL_write(st->ssl, data, len)) <= 0)
		return ssl_set_error(st->ssl, ret);

	return ret;
}

static ssize_t openssl_read(git_stream *stream, void *data, size_t len)
{
	openssl_stream *st = (openssl_stream *) stream;
	int ret;

	if ((ret = _SSL_read(st->ssl, data, len)) <= 0)
		return ssl_set_error(st->ssl, ret);

	return ret;
}

static int openssl_close(git_stream *stream)
{
	openssl_stream *st = (openssl_stream *) stream;
	int ret;

	if (st->connected && (ret = ssl_teardown(st->ssl)) < 0)
		return -1;

	st->connected = false;

	return st->owned ? git_stream_close(st->io) : 0;
}

static void openssl_free(git_stream *stream)
{
	openssl_stream *st = (openssl_stream *) stream;

	if (st->owned)
		git_stream_free(st->io);

	_SSL_free(st->ssl);
	git__free(st->host);
	git__free(st->cert_info.data);
	git__free(st);
}

static int openssl_stream_wrap(
	git_stream **out,
	git_stream *in,
	const char *host,
	int owned)
{
	openssl_stream *st;

	GIT_ASSERT_ARG(out);
	GIT_ASSERT_ARG(in);
	GIT_ASSERT_ARG(host);

	st = git__calloc(1, sizeof(openssl_stream));
	GIT_ERROR_CHECK_ALLOC(st);

	st->io = in;
	st->owned = owned;

	st->ssl = _SSL_new(git__ssl_ctx);
	if (st->ssl == NULL) {
		git_error_set(GIT_ERROR_SSL, "failed to create ssl object");
		git__free(st);
		return -1;
	}

	st->host = git__strdup(host);
	GIT_ERROR_CHECK_ALLOC(st->host);

	st->parent.version = GIT_STREAM_VERSION;
	st->parent.encrypted = 1;
	st->parent.proxy_support = git_stream_supports_proxy(st->io);
	st->parent.connect = openssl_connect;
	st->parent.certificate = openssl_certificate;
	st->parent.set_proxy = openssl_set_proxy;
	st->parent.read = openssl_read;
	st->parent.write = openssl_write;
	st->parent.close = openssl_close;
	st->parent.free = openssl_free;

	*out = (git_stream *) st;
	return 0;
}

int git_openssl_stream_wrap(git_stream **out, git_stream *in, const char *host)
{
	return openssl_stream_wrap(out, in, host, 0);
}

int git_openssl_stream_new(git_stream **out, const char *host, const char *port)
{
	git_stream *stream = NULL;
	int error;

	GIT_ASSERT_ARG(out);
	GIT_ASSERT_ARG(host);
	GIT_ASSERT_ARG(port);

	if ((error = git_socket_stream_new(&stream, host, port)) < 0)
		return error;

	if ((error = openssl_stream_wrap(out, stream, host, 1)) < 0) {
		git_stream_close(stream);
		git_stream_free(stream);
	}

	return error;
}

int git_openssl__set_cert_location(const char *file, const char *path)
{
	if (_SSL_CTX_load_verify_locations(git__ssl_ctx, file, path) == 0) {
		char errmsg[256];

		_ERR_error_string_n(_ERR_get_error(), errmsg, sizeof(errmsg));
		git_error_set(GIT_ERROR_SSL, "OpenSSL error: failed to load certificates: %s",
			errmsg);

		return -1;
	}
	return 0;
}

#else

#include "stream.h"
#include "git2/sys/openssl.h"

int git_openssl_stream_global_init(void)
{
	return 0;
}

int git_openssl_set_locking(void)
{
	git_error_set(GIT_ERROR_SSL, "libgit2 was not built with OpenSSL support");
	return -1;
}

#endif
