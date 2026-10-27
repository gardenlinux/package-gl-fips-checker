/*
 * gl-fips-checker.c — runs OpenSSL FIPS KAT tests and a few extra ones
 *
 * Usage:  ./gl-fips-checker [--host | --openssl | --full]
 *   --host     check /proc/sys/crypto/fips_enabled only
 *   --openssl  run OpenSSL FIPS self-tests only (default)
 *   --full     run --host and --openssl; both must pass
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/self_test.h>
#include <openssl/core_names.h>


#define CLR_GREEN  "\033[32m"
#define CLR_RED    "\033[31m"
#define CLR_RESET  "\033[0m"
#define MARK_PASS  CLR_GREEN "✓" CLR_RESET
#define MARK_FAIL  CLR_RED   "✗" CLR_RESET

typedef struct {
    int total;
    int passed;
    int failed;
} test_stats_t;

static test_stats_t g_stats;

static int self_test_callback(const OSSL_PARAM params[], void *arg __attribute__((unused)))
{
    const OSSL_PARAM *p;
    const char *phase = NULL, *type = NULL, *desc = NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING) return 0;
    phase = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING) return 0;
    type = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING) return 0;
    desc = (const char *)p->data;

    if (strcmp(phase, OSSL_SELF_TEST_PHASE_START) == 0) {
        g_stats.total++;
        printf("  %-35s %-30s  ", desc, type);
        fflush(stdout);
        return 1;
    }

    if (strcmp(phase, OSSL_SELF_TEST_PHASE_CORRUPT) == 0) return 1;

    if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0) {
        g_stats.passed++;
        printf(MARK_PASS "\n");
        return 1;
    }

    if (strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0) {
        g_stats.failed++;
        printf(MARK_FAIL "\n");
        return 1;
    }

    return 1;
}

typedef struct {
    OSSL_LIB_CTX  *libctx;
    OSSL_PROVIDER *fips;
} fips_ctx_t;

static void fips_ctx_cleanup(fips_ctx_t *ctx)
{
    OSSL_PROVIDER_unload(ctx->fips);
    OSSL_LIB_CTX_free(ctx->libctx);
}

static int fips_ctx_init(fips_ctx_t *ctx)
{
    ctx->libctx = OSSL_LIB_CTX_new();
    if (ctx->libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() failed\n");
        return 0;
    }

    if (OSSL_LIB_CTX_load_config(ctx->libctx, NULL) != 1) {
        fprintf(stderr, "Failed to load default OpenSSL config\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    OSSL_SELF_TEST_set_callback(ctx->libctx, self_test_callback, NULL);

    printf("OpenSSL FIPS Mode\n");
    int ossl_fips = EVP_default_properties_is_fips_enabled(ctx->libctx);
    printf("  fips=yes default properties: %s  %s\n",
           ossl_fips ? "enabled" : "disabled",
           ossl_fips ? MARK_PASS : MARK_FAIL);
    if (!ossl_fips) {
        printf("  " MARK_FAIL " OpenSSL is not in FIPS mode — aborting\n\n");
        return 0;
    }
    printf("\n");

    ctx->fips = OSSL_PROVIDER_load(ctx->libctx, "fips");
    if (ctx->fips == NULL) {
        fprintf(stderr,
                "Failed to load FIPS provider.\n"
                "Ensure the FIPS module .so is on OPENSSL_MODULES path.\n\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}

static int run_host_check(void)
{
    printf("Kernel FIPS Mode\n");
    FILE *fp = fopen("/proc/sys/crypto/fips_enabled", "r");
    if (fp == NULL) {
        printf("  /proc/sys/crypto/fips_enabled: not found  " MARK_FAIL "\n\n");
        return 0;
    }
    int val = -1;
    int r = fscanf(fp, "%d", &val);
    fclose(fp);
    if (r != 1) {
        printf("  /proc/sys/crypto/fips_enabled: unreadable  " MARK_FAIL "\n\n");
        return 0;
    }
    int ok = (val == 1);
    printf("  /proc/sys/crypto/fips_enabled = %d  %s\n",
           val, ok ? MARK_PASS : MARK_FAIL " (expected 1)");
    if (!ok)
        printf("  " MARK_FAIL " host is not in FIPS mode\n");
    printf("\n");
    return ok;
}

static void print_module_info(fips_ctx_t *ctx)
{
    char *ver = NULL, *buildinfo = NULL;
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_ptr("version",   &ver,       0);
    params[1] = OSSL_PARAM_construct_utf8_ptr("buildinfo", &buildinfo, 0);
    params[2] = OSSL_PARAM_construct_end();

    printf("Version Info\n");
    printf("  OpenSSL  %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("  built    %s\n", OpenSSL_version(OPENSSL_BUILT_ON));
    if (OSSL_PROVIDER_get_params(ctx->fips, params) && ver)
        printf("  FIPS     %s%s%s%s\n\n", ver,
               buildinfo ? "  (" : "",
               buildinfo ? buildinfo : "",
               buildinfo ? ")" : "");
    else
        printf("  FIPS     (version unavailable)\n\n");
}

static int check_digest(OSSL_LIB_CTX *libctx, const char *algo, int expect_available)
{
    static const unsigned char input[] = "gardenlinux";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_MD *md = EVP_MD_fetch(libctx, algo, "fips=yes");
    if (md == NULL) {
        if (!expect_available) {
            printf("  " MARK_PASS " %-8s blocked under FIPS\n", algo);
            return 1;
        }
        printf("  " MARK_FAIL " %-8s not available under FIPS\n", algo);
        return 0;
    }
    if (!expect_available) {
        printf("  " MARK_FAIL " %-8s should be blocked under FIPS\n", algo);
        EVP_MD_free(md);
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx != NULL
          && EVP_DigestInit_ex(ctx, md, NULL) == 1
          && EVP_DigestUpdate(ctx, input, sizeof(input) - 1) == 1
          && EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1;

    printf("  %s %-8s %s\n", ok ? MARK_PASS : MARK_FAIL, algo,
           ok ? "digest computed" : "digest failed");

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ok;
}

static int check_fips_digests(OSSL_LIB_CTX *libctx)
{
    printf("\nFIPS Digest Check\n");
    int ok = 1;
    ok &= check_digest(libctx, "SHA1",    1);
    ok &= check_digest(libctx, "SHA-256", 1);
    ok &= check_digest(libctx, "SHA-384", 1);
    ok &= check_digest(libctx, "SHA-512", 1);
    ok &= check_digest(libctx, "MD5",     0);
    return ok;
}

static int run_openssl_check(void)
{
    fips_ctx_t ctx = {0};
    if (!fips_ctx_init(&ctx)) {
        fips_ctx_cleanup(&ctx);
        return 0;
    }

    print_module_info(&ctx);

    printf("On-Demand Self-Tests\n");
    if (!OSSL_PROVIDER_self_test(ctx.fips))
        printf("  On-demand self-test failed or not supported.\n");
    int kats_ok = (g_stats.failed == 0 && g_stats.total > 0);
    if (g_stats.total > 0)
        printf("  %d passed, %d failed  %s\n", g_stats.passed, g_stats.failed,
               kats_ok ? MARK_PASS : MARK_FAIL);

    int digests_ok = check_fips_digests(ctx.libctx);

    printf("\nOpenSSL Summary\n");
    printf("  OpenSSL FIPS mode %s\n", MARK_PASS);
    printf("  KAT self-tests    %s\n", kats_ok    ? MARK_PASS : MARK_FAIL);
    printf("  Digest checks     %s\n", digests_ok ? MARK_PASS : MARK_FAIL);

    fips_ctx_cleanup(&ctx);
    return kats_ok && digests_ok;
}

int main(int argc, char *argv[])
{
    int do_host    = 0;
    int do_openssl = 1;

    if (argc > 1) {
        if (strcmp(argv[1], "--host") == 0) {
            do_host    = 1;
            do_openssl = 0;
        } else if (strcmp(argv[1], "--openssl") == 0) {
            do_host    = 0;
            do_openssl = 1;
        } else if (strcmp(argv[1], "--full") == 0) {
            do_host    = 1;
            do_openssl = 1;
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: %s [--host | --openssl | --full | --help]\n\n"
                   "  --host     Check if the host kernel has FIPS enabled\n"
                   "             (/proc/sys/crypto/fips_enabled must be 1)\n\n"
                   "  --openssl  Run OpenSSL FIPS checks (default):\n"
                   "               - Verify OpenSSL is running in FIPS mode\n"
                   "               - Run on-demand KAT self-tests via the FIPS provider\n"
                   "               - Verify SHA1/SHA-256/SHA-384/SHA-512 are available and functional\n"
                   "               - Verify MD5 is blocked under FIPS\n\n"
                   "  --full     Run both --host and --openssl; both must pass\n\n"
                   "  -h, --help Show this help and exit\n",
                   argv[0]);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "Usage: %s [--host | --openssl | --full | --help]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    int host_ok    = 1;
    int openssl_ok = 1;

    if (do_host)
        host_ok = run_host_check();
    if (do_openssl)
        openssl_ok = run_openssl_check();

    if (do_host && do_openssl) {
        printf("\nSummary\n");
        printf("  Host FIPS mode    %s\n", host_ok    ? MARK_PASS : MARK_FAIL);
        printf("  OpenSSL checks    %s\n", openssl_ok ? MARK_PASS : MARK_FAIL);
    }

    if (host_ok && openssl_ok) {
        printf("\n  " MARK_PASS " all checks passed\n\n");
        return EXIT_SUCCESS;
    } else {
        printf("\n  " MARK_FAIL " one or more checks failed\n\n");
        return EXIT_FAILURE;
    }
}
