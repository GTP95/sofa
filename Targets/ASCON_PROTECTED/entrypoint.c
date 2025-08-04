// Default includes, do not change these
#include <Firmware/hal/hal.h>
#include <Firmware/simpleserial/simpleserial.h>
#include <stdint.h>
#include <stdlib.h>

// Default defines, do not change these
#ifdef PTLEN
 #define PLAINTEXT_LEN PTLEN
#else
 #define PLAINTEXT_LEN 64
#endif

// User includes (add the includes needed to perform the cryptographic operation)
#include "crypto_aead.h"
#include "ascon.h"
#include "permutations.h"

// User defines
#define ASCON_KEY_LEN 16 // for this version of ASCON these 2 are always the same
#define ASCON_NPUB_LEN 16

#ifdef AD_LEN
 #define ASCON_AD_LEN AD_LEN
#else
 #define ASCON_AD_LEN 0
#endif

// number of bytes
#define LENGTH(len) (len)

// User globals

unsigned char* p = NULL;
unsigned char* c = NULL;
unsigned char* a = NULL;
unsigned char* n = NULL;
unsigned char* k = NULL;

unsigned long long ctlen = 0;
unsigned long long adlen = 0;
unsigned long long len = 0;

// Function to return the value to the host
void return_value(uint8_t* data, uint8_t data_len)
{
    simpleserial_put('r', data_len, data);
}

// General function for setting the encryption key
uint8_t set_key(uint8_t* key, uint8_t k_len)
{
    len = LENGTH(k_len) * sizeof(*k);

    if (k) free (k);
    k = malloc(len);

    // Check for malloc fail
    if (k == NULL) return 0x01;

    memcpy(k, key, len);

    return 0x0;
}

// General function for setting the nonce
uint8_t set_nonce(uint8_t* nonce, uint8_t n_len)
{
    len = LENGTH(n_len) * sizeof(*n);

    if (n) free(n);
    n = malloc(len);

    // Check for malloc fail
    if (n == NULL) return 0x01;

    memcpy(n, nonce, len);

    return 0x0;
}

// General function for setting associated data
uint8_t set_associated_data(uint8_t* ad, uint8_t ad_len)
{
    len = LENGTH(ad_len) * sizeof(*a);

    if (a) free(a);
    a = malloc(len);

    // Check for malloc fail
    if (a == NULL) return 0x01;

    memcpy(a, ad, len);

    return 0x0;
}

// General function for receiving the plaintext and starting the cryptographic operation
uint8_t encrypt_plaintext(uint8_t* plaintext, uint8_t pt_len)
{
    len = LENGTH(pt_len) * sizeof(*plaintext);

    if (p) free(p);
    p = malloc(len);

    // Check for malloc fail
    if (p == NULL) return 0x01;

    memcpy(p, plaintext, len);

    ctlen = pt_len + CRYPTO_ABYTES;

    len = LENGTH(ctlen) * sizeof(*c);

    if (c) free(c);
    c = malloc(len);

    // Check for malloc fail
    if (c == NULL) return 0x01;

    crypto_aead_encrypt(c, &ctlen, p, pt_len, a, ASCON_AD_LEN, NULL, n, k);

    return_value(c, ctlen);

    if (p) {
        free(p);
        p = NULL;
    }
    if (c) {
        free(c);
        c = NULL;
    }
    if (a) {
        free(a);
        a = NULL;
    }
    if (n) {
        free(n);
        n = NULL;
    }
    if (k) {
        free(k);
        k = NULL;
    }

    return 0x00;
}

// Hook that does nothing but it is useful to the Qiling side to figure out when we
// Registered all the commands, DO NOT REMOVE!
uint8_t quit(uint8_t* plaintext, uint8_t pt_len)
{
    return 0x00;
}

int main(void)
{
    /*
        Set up the platform, the UART and the the special simpleserial commands (v, w, y)
        v = check SS version, returns "z{SS_VER}\n"
        w = get the registered commands, returns "r[(COMMAND,EXPECTED_DATA_LENGTH)]z00\n"
        y = gets the number of registered commands, returns "r{NR_COMMANDS}z00\n"
        The working version is SS_VER_1_1, maybe 1_0, but not >= 2_0.
        DO NOT REMOVE.
    */
    platform_init();
    init_uart();
	simpleserial_init();

    /* 
        User defined commands, based on the cryptographic operation, max 16 total (predefined + users's) allowed.
        Examples:
            simpleserial_addcmd('k', 16, set_key);
            simpleserial_addcmd('n', 16, set_nonce);
            simpleserial_addcmd('a', 16, set_associated_data);
            simpleserial_addcmd('p', 64, encrypt_plaintext);
    */
    simpleserial_addcmd('k', ASCON_KEY_LEN, set_key);
    simpleserial_addcmd('n', ASCON_NPUB_LEN, set_nonce);
    simpleserial_addcmd('a', ASCON_AD_LEN, set_associated_data);
    simpleserial_addcmd('p', PLAINTEXT_LEN, encrypt_plaintext);

    // Special command that does nothing but tells Qiling that we are done with adding commands.
    simpleserial_addcmd('q', 0, quit);

    /* 
        Main entry loop, waiting for commands.
    */ 
    while(1)
        simpleserial_get();
}
