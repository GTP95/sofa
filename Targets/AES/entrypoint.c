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

// User headers (add the headers needed to perfom the cryptografic operation)
#include <aes.h>
// User headers

// User globals
struct AES_ctx ctx;
// User globals

// Function to return the value to the host
void return_value(uint8_t* data, uint8_t data_len)
{
    simpleserial_put('r', data_len, data);
}

// General function for setting the encyption key
uint8_t set_key(uint8_t* key, uint8_t k_len)
{
    AES_init_ctx(&ctx, key);
    return 0x00;
}

// General function for setting the IV in AES
// Mind that the IV needs to be 16 bytes.
uint8_t set_iv(uint8_t* iv, uint8_t iv_len)
{
    AES_ctx_set_iv(&ctx, iv);
    return 0x00;
}

// General function to send the plaintext and start the cryptografic operation
uint8_t encrypt_plaintext(uint8_t* plaintext, uint8_t pt_len)
{
    uint8_t i;
    uint8_t nr_blocks = pt_len/AES_BLOCKLEN;

    #if (CBC == 1)
        AES_CBC_encrypt_buffer(&ctx, plaintext, pt_len);
    #elif (CTR == 1)
        AES_CTR_xcrypt_buffer(&ctx, plaintext, pt_len);
    #else
        // This implementation of AES encrypts in blocks of 16 bytes for ECB
        for (i = 0; i < nr_blocks; ++i)
        {
            AES_ECB_encrypt(&ctx, plaintext + (i * 16));
        }
    #endif
    
    // Send the result back to the capture board.
    return_value(plaintext, pt_len);
    return 0x00;
}

// Hook that does nothing but it is useful to the Qiling side to figure out when we
// Registered all the commands, DO NOT REMOVE!
uint8_t done(uint8_t* plaintext, uint8_t pt_len)
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

    // User defined commands, based on the cryptographic operation, max 16 total (predefined + users's) allowed.
    
    // Add set key command
    simpleserial_addcmd('k', AES_KEYLEN, set_key);

    // Only ECB doens't use IVs
    #if (ECB != 1)
        // Add set IVs command
        simpleserial_addcmd('i', AES_BLOCKLEN, set_iv);
    #endif

    // Add encrypt command
    simpleserial_addcmd('p', PLAINTEXT_LEN, encrypt_plaintext);

    // Special command that does nothing but tells Qiling that we are done with adding commands.
    simpleserial_addcmd('q', 0, done);

    // Main entry loop, waiting for commands, if the right format of a registered command is not provided,
    // usually nothing is returned (so nice, right!?). We could implement better error handling but then
    // we would deviate form the ChipWhisperer implementation of SimpleSerial.
    while(1)
        simpleserial_get();
}
