// Default includes, do not change these
#include <Firmware/hal/hal.h>
#include <Firmware/simpleserial/simpleserial.h>
#include <stdint.h>
#include <stdlib.h>

// User includes
#include "keccak.h" 

// Default defines, do not change these
#ifdef PTLEN
 #define INPUT_LEN PTLEN
#else
 #define INPUT_LEN 64
#endif

// User defines
#ifdef OPLEN
 #define OUTPUT_LEN OPLEN
#else
 #define OUTPUT_LEN 64
#endif

#ifndef LITTLE_ENDIAN
 #define LITTLE_ENDIAN 1
#endif

// User globals

// Function for performing SHAKE128
uint8_t shake_hash(uint8_t* input, uint8_t i_len)
{
    unsigned char output[OUTPUT_LEN] = {0};

    #if (FUNC == SHAKE128)
        // Call SHAKE128 function
        FIPS202_SHAKE128(input, i_len, output, OUTPUT_LEN);
    #elif (FUNC == SHAKE256)
        FIPS202_SHAKE256(input, i_len, output, OUTPUT_LEN);
    #else
        return 0x01
    #endif
    
    // Send the result back to Qiling through usart1
    simpleserial_put('r', OUTPUT_LEN, output);

    return 0x00;
}

// Hook that does nothing but it is useful to the Qiling side to figure out when we registered all the commands
uint8_t quit(uint8_t* plaintext, uint8_t pt_len)
{
    return 0x00;
}

int main(void)
{
    /*
        Set up the platform, the UART and the special simpleserial commands (v, w, y)
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
        User defined commands, based on the cryptographic operation, max 16 total (predefined + user's) allowed.
        Examples:
            simpleserial_addcmd('i', 64, set_input_data);   // Command 'i' for input
            simpleserial_addcmd('s', 0, shake128_hash);     // Command 's' for SHAKE128
            simpleserial_addcmd('t', 0, shake256_hash);     // Command 't' for SHAKE256
    */

    simpleserial_addcmd('p', INPUT_LEN, shake_hash);         // Compute SHAKE hashing
    simpleserial_addcmd('q', 0, quit);                       // Quit

    /* 
        Main entry loop, waiting for commands
    */
    while(1)
        simpleserial_get();
}
