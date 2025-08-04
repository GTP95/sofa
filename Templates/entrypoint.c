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

// User includes (add the includes needed to perfom the cryptografic operation)

// User includes

// User defines (add the defines needed to perfom the cryptografic operation)

// User defines

// User globals (add the globals needed to perfom the cryptografic operation)

// User globals

// General function for setting the mask (if supported by the algorithm)
uint8_t set_mask(uint8_t* key, uint8_t k_len)
{
    return 0x00;
}

// General function for setting the encyption key
uint8_t set_key(uint8_t* key, uint8_t k_len)
{
    return 0x00;
}

// General function for receiving the plaintext and starting the cryptografic operation
uint8_t encrypt_plaintext(uint8_t* plaintext, uint8_t pt_len)
{
    // Send the result back to Qiling through usart1
    simpleserial_put('r', pt_len, plaintext);
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
        Implementation details: https://chipwhisperer.readthedocs.io/en/latest/simpleserial.html#simpleserial-addcmd
        Examples:
            simpleserial_addcmd('k', 16, set_key);
            simpleserial_addcmd('p', 64, encrypt_plaintext);
    */

    // Special command that does nothing but tells Qiling that we are done with adding commands.
    simpleserial_addcmd('q', 0, quit);

    /* 
        Main entry loop, waiting for commands, if the right format of a registered command is not provided,
        usually nothing is returned (so nice, right!?). We could implement better error handling but then
        we would deviate form the ChipWhisperer implementation of SimpleSerial.
    */ 
    while(1)
        simpleserial_get();
}
