ifeq ($(PLATFORM),)
  -include Makefile.platform
  ifeq ($(PLATFORM),)
    PLATFORM=NONE
  else
    ${info using saved PLATFORM '$(PLATFORM)'}
  endif
endif


include $(FIRMWAREPATH)/hal/Makefile.hal
include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial

#Debug - can be useful to see variables
#${info '$(.VARIABLES)'}

# Add the platform to the output filenames
TARGET-PLAT = $(TARGET)-$(PLATFORM)

# Also get target names for all platforms (for make clean)
TARGET-ALL = $(foreach PLAT,$(PLATFORM_LIST), $(TARGET)-$(PLAT))

# Object files directory
#     To put object files in current directory, use a dot (.), do NOT make
#     this an empty or blank macro!
OBJDIR = OBJFILES-$(TARGET-PLAT)

# List C source files here. (C dependencies are automatically generated.)
SRC +=

# List Assembler source files here.
#     Make them always end in a capital .S.  Files ending in a lowercase .s
#     will not be considered source files but generated files (assembler
#     output from the compiler), and will be deleted upon "make clean"!
#     Even though the DOS/Win* filesystem matches both .s and .S the same,
#     it will preserve the spelling of the filenames, and gcc itself does
#     care about how the name is spelled on its command-line.
ASRC +=

ifeq ($(CPPSRC),)
  LINK_COMPILER=$(CC)
else
  LINK_COMPILER=$(CXX)
endif

##########################################################################
##########################################################################

#VPATH +=

# Optimization level, can be [0, 1, 2, 3, s].
#     0 = turn off optimization. s = optimize for size.
#     (Note: 3 is not always the best optimization level. See avr-libc FAQ.)
ifeq ($(OPT),)
  OPT = s
endif


# Debugging format.
#     Native formats for AVR-GCC's -g are dwarf-2 [default] or stabs.
#     AVR Studio 4.10 requires dwarf-2.
#     AVR [Extended] COFF format requires stabs, plus an avr-objcopy run.
DEBUG = dwarf-2


# List any extra directories to look for include files here.
#     Each directory must be seperated by a space.
#     Use forward slashes for directory separators.
#     For a directory that has spaces, enclose it in quotes.
EXTRAINCDIRS +=


# Compiler flag to set the C Standard level.
#     c89   = "ANSI" C
#     gnu89 = c89 plus GCC extensions
#     c99   = ISO C99 standard (not yet fully implemented)
#     gnu99 = c99 plus GCC extensions
CSTANDARD = -std=gnu99


# Place -D or -U options here for C sources
CDEFS += -DF_CPU=$(F_CPU)UL -DSS_VER_2_0=2 -DSS_VER_2_1=3 -DSS_VER_1_1=1 -DSS_VER_1_0=0


# Place -D or -U options here for ASM sources
ADEFS += -DF_CPU=$(F_CPU)


#---------------- Compiler Options C ----------------
#  -g*:          generate debugging information
#  -O*:          optimization level
#  -f...:        tuning, see GCC manual and avr-libc documentation
#  -Wall...:     warning level
#  -Wa,...:      tell GCC to pass this to the assembler.
#    -adhlns...: create assembler listing
CFLAGS += -g$(DEBUG)
CFLAGS += $(CDEFS)
CFLAGS += -O$(OPT)
CFLAGS += -funsigned-char
CFLAGS += -funsigned-bitfields
CFLAGS += -fshort-enums
CFLAGS += -Wall
CFLAGS += -Wstrict-prototypes
#CFLAGS += -mshort-calls
#CFLAGS += -fno-unit-at-a-time
#CFLAGS += -Wundef
#CFLAGS += -Wunreachable-code
#CFLAGS += -Wsign-compare
CFLAGS += $(patsubst %,-I%,$(EXTRAINCDIRS))
CFLAGS += $(CSTANDARD)
CFLAGS += -Wno-discarded-qualifiers -Wno-unused-function -Wno-unused-variable -Wno-strict-prototypes -Wno-missing-prototypes
CFLAGS += -Wno-pointer-sign -Wno-unused-value -Wno-implicit-function-declaration

#Flags that must come at end of list can be specified with CFLAGS_LAST
CFLAGS += $(CFLAGS_LAST)

# has to come after we hijack for CPP flags
CFLAGS += -Wa,-adhlns=$(addprefix $(OBJDIR)/,$(notdir $(<:%.c=%.lst)))

#---------------- Assembler Options ----------------
#  -Wa,...:   tell GCC to pass this to the assembler.
#  -adhlns:   create listing
#  -gstabs:   have the assembler create line number information; note that
#             for use in COFF files, additional information about filenames
#             and function names needs to be present in the assembler source
#             files -- see avr-libc docs [FIXME: not yet described there]
#  -listing-cont-lines: Sets the maximum number of continuation lines of hex
#       dump that will be displayed for a given single line of source input.

#-adhlns=$(<:%.S=$(OBJDIR)/%.lst),
#,--listing-cont-lines=100

ASFLAGS += $(ADEFS) -Wa,-gstabs,-adhlns=$(addprefix $(OBJDIR)/,$(notdir $(<:%.S=%.lst)))
ASFLAGS += $(patsubst %,-I%,$(EXTRAINCDIRS))


VERBOSE ?= false

ifeq ($(VERBOSE), false)
	COMPMSG = "    $< ..."
	COMPCPPMSG = "    $< ..."
	LINKMSG = "    $@ ..."
	DONEMSG = "Done!"
else
	COMPMSG   = "    $(CC) -c $(ALL_CFLAGS) $< -o $@ ..."
	COMPCPPMSG   = "    $(CXX) -c $(ALL_CFLAGS) $< -o $@ ..."
	LINKMSG = "    $(LINK_COMPILER) $@ w/ opts $(ALL_CFLAGS) $(LDFLAGS) ... $^"
	DONEMSG = "Done!\n"
endif


#---------------- Linker Options ----------------
#  -Wl,...:     tell GCC to pass this to linker.
#    -Map:      create map file
#    --cref:    add cross reference to  map file
LDFLAGS += -Wl,-Map=$(TARGET-PLAT).map,--cref

#============================================================================

# Define programs and commands.
SHELL = sh

REMOVE = rm -f --
REMOVEDIR = rm -rf
COPY = cp
WINSHELL = cmd
#Depending on if echo is unix or windows, they respond differently to no arguments. Windows will annoyingly
#print "echo OFF", so instead we're forced to give it something to echo. The windows one will also print
#passed ' or " symbols, so we use a . as it's pretty small...
ECHO_BLANK = echo .
ifeq ($(OS),Windows_NT)
	AdjustPath = $(addprefix $1\, $(subst /,\,$2 ) )
	MAKEDIR = @mkdir
else
	AdjustPath = $(addprefix $1/, $2)
	MAKEDIR = @mkdir -p
endif

# Define Messages
# English
MSG_ERRORS_NONE = Errors: none
MSG_SIZE_BEFORE = Size before:
MSG_SIZE_AFTER = Size after:
MSG_FLASH = Creating load file for Flash:
MSG_EEPROM = Creating load file for EEPROM:
MSG_EXTENDED_LISTING = Creating Extended Listing:
MSG_SYMBOL_TABLE = Creating Symbol Table:
MSG_LINKING = Linking:
MSG_COMPILING = Compiling C:
MSG_COMPILING_CPP = Compiling C++:
MSG_ASSEMBLING = Assembling:
MSG_CLEANING = Cleaning project:
MSG_CREATING_LIBRARY = Creating library:

# Define all object files.
OBJ = $(SRC:%.c=$(OBJDIR)/%.o) $(CPPSRC:%.cpp=$(OBJDIR)/%.o) $(ASRC:%.S=$(OBJDIR)/%.o)

# Define all listing files.
LST = $(SRC:%.c=$(OBJDIR)/%.lst) $(CPPSRC:%.cpp=$(OBJDIR)/%.lst) $(ASRC:%.S=$(OBJDIR)/%.lst)

# Compiler flags to generate dependency files.
GENDEPFLAGS = -MMD -MP -MF .dep/$(@F).d

# Combine all necessary flags and optional flags.
# Add target processor to flags.
ALL_CFLAGS = $(MCU_FLAGS) -I. $(CFLAGS) $(GENDEPFLAGS)
ALL_ASFLAGS = $(MCU_FLAGS) -I. -x assembler-with-cpp $(ASFLAGS)

allquick: .dep begin gccversion build create_config sizeafter end

# Change the build target to build a HEX file or a library.
build: elf hex bin eep lss sym

elf: $(TARGET-PLAT).elf
hex: $(TARGET-PLAT).hex
bin: $(TARGET-PLAT).bin
eep: $(TARGET-PLAT).eep
lss: $(TARGET-PLAT).lss
sym: $(TARGET-PLAT).sym
json := $(TARGET-PLAT).json
LIBNAME=lib$(TARGET-PLAT).a
lib: $(LIBNAME)

begin:
	@$(ECHO_BLANK)

create_config:
ifeq ($(TARGET),AES)
	@echo "{"> $(json)
	@echo "  \"platform\": \"$(PLATFORM)\"," >> $(json)
	@echo "  \"__platform__comment\": \"The hardware platform used for this operation (e.g., CW308_STM32F4)\"," >> $(json)
	@echo "  \"target\": \"$(TARGET)\"," >> $(json)
	@echo "  \"__target__comment\": \"The specific target profile or algorithm being used (e.g., AES, ASCON, KECCAK)\"," >> $(json)
	@echo "  \"key_length\": \"$(KEYSIZE)\"," >> $(json)
	@echo "  \"__key_length__comment\": \"The length of the encryption key in bits (e.g., 128, 192, 256)\"," >> $(json)
	@echo "  \"plaintext_length\": \"$(PTLEN)\"," >> $(json)
	@echo "  \"__plaintext_length__comment\": \"The length of the plaintext input in bytes (e.g., 64 bytes)\"," >> $(json)
	@echo "  \"use_iv\": \"$$(if [ \"$(MODE)\" = \"ECB\" ]; then echo false; else echo true; fi)\"," >> $(json)
	@echo "  \"__use_iv__comment\": \"Boolean value indicating whether an initialization vector (IV) is used; false for ECB mode, true otherwise\"," >> $(json)
	@echo "  \"masked\": \"$$(if [ \"$(MASKED)\" = \"1\" ]; then echo true; else echo false; fi)\"," >> $(json)
	@echo "  \"__masked__comment\": \"Boolean value indicating whether masking is enabled for side-channel resistance (true if masked, false otherwise)\"" >> $(json)
	@echo "}" >> $(json)
else ifeq ($(filter $(TARGET), ASCON_REF ASCON_PROTECTED ASCON_ARM), $(TARGET))
	@echo "{"> $(json)
	@echo "  \"platform\": \"$(PLATFORM)\"," >> $(json)
	@echo "  \"__platform__comment\": \"The hardware platform used for this operation (e.g., CW308_STM32F4)\"," >> $(json)
	@echo "  \"target\": \"$(TARGET)\"," >> $(json)
	@echo "  \"__target__comment\": \"The specific target profile or algorithm being used (e.g., ASCON)\"," >> $(json)
	@echo "  \"plaintext_length\": \"$(PTLEN)\"," >> $(json)
	@echo "  \"__plaintext_length__comment\": \"The length of the plaintext input in bytes (e.g., 64 bytes)\"," >> $(json)
	@echo "  \"ad_length\": \"$(AD_LEN)\"," >> $(json)
	@echo "  \"__ad_length__comment\": \"The length of the associated data input in bytes (e.g., 16 bytes)\"," >> $(json)
	@echo "  \"num_shares\": \"$(NUM_SHARES)\"," >> $(json)
	@echo "  \"__num_shares__comment\": \"The number of shares used for masking\"," >> $(json)
	@echo "  \"pa_rounds\": \"$(PA_ROUNDS)\"," >> $(json)
	@echo "  \"__pa_rounds__comment\": \"The number of PA rounds (full rounds) in the ASCON algorithm\"," >> $(json)
	@echo "  \"pb_rounds\": \"$(PB_ROUNDS)\"," >> $(json)
	@echo "  \"__pb_rounds__comment\": \"The number of PB rounds (partial rounds) in the ASCON algorithm\"," >> $(json)
	@echo "  \"ror_shares\": \"$(ROR_SHARES)\"," >> $(json)
	@echo "  \"__ror_shares__comment\": \"Number of shares rotated in ASCON to mitigate side-channel attacks\"," >> $(json)
	@echo "  \"extern_bi\": \"$$(if [ \"$(EXTERN_BI)\" = \"1\" ]; then echo true; else echo false; fi)\"," >> $(json)
	@echo "  \"__extern_bi__comment\": \"Indicates if external bit interleaving is used\"" >> $(json)
	@echo "}" >> $(json)
else ifeq ($(TARGET),KECCAK)
	@echo "{"> $(json)
	@echo "  \"platform\": \"$(PLATFORM)\"," >> $(json)
	@echo "  \"__platform__comment\": \"The hardware platform used for this operation (e.g., CW308_STM32F4)\"," >> $(json)
	@echo "  \"target\": \"$(TARGET)\"," >> $(json)
	@echo "  \"__target__comment\": \"The specific target profile or algorithm being used (e.g., KECCAK)\"," >> $(json)
	@echo "  \"function\": \"$(FUNC)\"," >> $(json)
	@echo "  \"__function__comment\": \"The specific function of the KECCAK family (e.g., SHAKE128)\"," >> $(json)
	@echo "  \"plaintext_length\": \"$(PTLEN)\"," >> $(json)
	@echo "  \"__plaintext_length__comment\": \"The length of the plaintext input in bytes (e.g., 64 bytes)\"," >> $(json)
	@echo "  \"digest_length\": \"$(OPLEN)\"," >> $(json)
	@echo "  \"__digest_length__comment\": \"The length of the digest in bytes (e.g., 64 bytes)\"" >> $(json)
	@echo "}" >> $(json)
else
	@echo "No valid TARGET specified or TARGET not recognized."
	@echo "Please specify TARGET={AES, ASCON, or KECCAK}."
endif

end:
	@echo   +--------------------------------------------------------
	@echo   + Built for platform "$(if $(PLTNAME),$(PLTNAME),UNKNOWN)" with:
	@echo   +      CRYPTO_TARGET  = "$(if $(TARGET),$(TARGET),UNKNOWN)"
	@echo   +      CRYPTO_OPTIONS = "$(if $(CRYPTO_OPTIONS),$(CRYPTO_OPTIONS),UNKNOWN)"
	@echo   +      COMPILER OPT   = "$(if $(OPT),-O$(OPT),UNKNOWN)"
	@echo   +--------------------------------------------------------


fastnote:
	@echo   +--------------------------------------------------------
	@echo   + Default target does full rebuild each time.
	@echo   + Specify buildtarget == allquick == to avoid full rebuild
	@echo   +--------------------------------------------------------

help:
ifeq ($(TARGET),AES)
	@echo "+--------------------------------------------------------"
	@echo "+ AES Settings:"
	@echo "+      MODE    | Options: ECB, CBC, CTR | Default: ECB"
	@echo "+      KEYSIZE | Options: 128, 192, 256 | Default: 128"
	@echo "+      MASKED  | Options: 0, 1          | Default: 0"
	@echo "+--------------------------------------------------------"
else ifeq ($(filter $(TARGET), ASCON_REF ASCON_PROTECTED ASCON_ARM), $(TARGET))
	@echo "+--------------------------------------------------------"
	@echo "+ $(TARGET) Settings:"
	@echo "+      AD_LEN      | Bytes of AD, 0 = No AD   | Default: 0"
	@echo "+      PA_ROUNDS   | Options: 2, 6, 12        | Default: 12"
	@echo "+      PB_ROUNDS   | Options: 2, 6            | Default: 6"
	@echo "+      NUM_SHARES  | Options: 1, 2, 3, 4      | Default: 1"
	@echo "+      ROR_SHARES  | Options: (customizable)  | Default: 5"
	@echo "+      EXTERN_BI   | Options: 0, 1            | Default: 0"
	@echo "+--------------------------------------------------------"
else ifeq ($(TARGET),KECCAK)
	@echo "+--------------------------------------------------------"
	@echo "+ KECCAK Settings:"
	@echo "+      FUNC     | Options: SHAKE128, SHAKE256 | Default: SHAKE128"
	@echo "+      OPLEN    | Bytes of digest             | Default: 64"
	@echo "+--------------------------------------------------------"
else
	@echo "+--------------------------------------------------------"
	@echo "+ General usage:" 
	@echo "+      make TARGET={TARGET} [TARGET_SETTINGS] [PTLEN={PLAINTEXT_LENGTH}] OPT={OPT_LVL}"
	@echo "+--------------------------------------------------------"
	@echo "+ GCC Compiler optimization:" 
	@echo "+      OPT      | Options: 0, 1, 2, 3, s | Default: s"
	@echo "+--------------------------------------------------------"
	@echo "+ Commands available:"
	@echo "+      make help                                     | Displays usage and options for all targets"
	@echo "+      make TARGET={TARGET} help                     | Displays the options available for that target"
	@echo "+      make TARGET={TARGET} PTLEN={PLAINTEXT_LENGTH} | Builds the target expenting PTLEN bytes of plaintext"
	@echo "+      make TARGET={TARGET} clean                    | Clean the objects created by the build for that target"
	@echo "+--------------------------------------------------------"
	@echo "+ Available Targets:"
	@echo "+      AES      | Implementation of masked AES"
	@echo "+               | Link: https://github.com/CENSUS/masked-aes-c"
	@echo "+      ASCON    | Implementation of ASCON128v12 PROTECTED"
	@echo "+               | Link: https://github.com/ascon/simpleserial-ascon"
	@echo "+      KECCAK   | Keccak Hashing (SHAKE128, SHAKE256)"
	@echo "+               | Link: https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c"
	@echo "+--------------------------------------------------------"
	@echo "+ Plaintext Settings:"
	@echo "+      PTLEN   | AES: Multiple of 16 bytes for ECB and CBC, if not, they will be padded using PKCS7"
	@echo "+              | ASCON: Multiple of 8 bytes, if not, they will be padded by the current implementation"
	@echo "+              | KECCAK: Any input size, limited by SimpleSerial 1.1 capacity, < 250 bytes"
	@echo "+              | Default value: 64 (bytes)"
	@echo "+--------------------------------------------------------"
	@echo "+ AES Settings:"
	@echo "+      MODE    | Options: ECB, CBC, CTR | Default: ECB"
	@echo "+      KEYSIZE | Options: 128, 192, 256 | Default: 128"
	@echo "+      MASKED  | Options: 0, 1          | Default: 0"
	@echo "+--------------------------------------------------------"
	@echo "+ ASCON 128v12 PROTECTED Settings:"
	@echo "+      AD_LEN      | Bytes of AD, 0 = No AD   | Default: 0"
	@echo "+      PA_ROUNDS   | Options: 2, 6, 12        | Default: 12"
	@echo "+      PB_ROUNDS   | Options: 2, 6            | Default: 6"
	@echo "+      NUM_SHARES  | Options: 1, 2, 3, 4      | Default: 1"
	@echo "+      ROR_SHARES  | Options: (customizable)  | Default: 5"
	@echo "+      EXTERN_BI   | Options: 0, 1            | Default: 0"
	@echo "+--------------------------------------------------------"
	@echo "+ KECCAK Settings:"
	@echo "+      FUNC     | Options: SHAKE128, SHAKE256 | Default: SHAKE128"
	@echo "+      OPLEN    | Bytes of digest             | Default: 64"
	@echo "+--------------------------------------------------------"
endif

# Display size of file.
HEXSIZE = $(SIZE) --target=ihex $(TARGET-PLAT).hex

# Note: custom ELFSIZE command can be specified in Makefile.platform
# See avr/Makefile.avr for example
ifeq ($(ELFSIZE),)
  ELFSIZE = $(SIZE) $(TARGET-PLAT).elf
endif

sizeafter: build
	@echo $(MSG_SIZE_AFTER)
	@$(ELFSIZE)

$(OBJ): | $(OBJDIR)

$(OBJDIR):
	$(MAKEDIR) $(OBJDIR) $(call AdjustPath,$(OBJDIR),$(MKDIR_LIST) )

.dep:
	$(MAKEDIR) .dep

# Display compiler version information.
gccversion :
	@$(CC) --version



# Program the device.
program: $(TARGET-PLAT).hex $(TARGET-PLAT).eep
	$(AVRDUDE) $(AVRDUDE_FLAGS) $(AVRDUDE_WRITE_FLASH) $(AVRDUDE_WRITE_EEPROM)


# Generate avr-gdb config/init file which does the following:
#     define the reset signal, load the target file, connect to target, and set
#     a breakpoint at main().
gdb-config:
	@$(REMOVE) $(GDBINIT_FILE)
	@echo define reset >> $(GDBINIT_FILE)
	@echo SIGNAL SIGHUP >> $(GDBINIT_FILE)
	@echo end >> $(GDBINIT_FILE)
	@echo file $(TARGET-PLAT).elf >> $(GDBINIT_FILE)
	@echo target remote $(DEBUG_HOST):$(DEBUG_PORT)  >> $(GDBINIT_FILE)
ifeq ($(DEBUG_BACKEND),simulavr)
	@echo load  >> $(GDBINIT_FILE)
endif
	@echo break main >> $(GDBINIT_FILE)

debug: gdb-config $(TARGET-PLAT).elf
ifeq ($(DEBUG_BACKEND), avarice)
	@echo Starting AVaRICE - Press enter when "waiting to connect" message displays.
	@$(WINSHELL) /c start avarice --jtag $(JTAG_DEV) --erase --program --file \
	$(TARGET-PLAT).elf $(DEBUG_HOST):$(DEBUG_PORT)
	@$(WINSHELL) /c pause

else
	@$(WINSHELL) /c start simulavr --gdbserver --device $(MCU) --clock-freq \
	$(DEBUG_MFREQ) --port $(DEBUG_PORT)
endif
	@$(WINSHELL) /c start avr-$(DEBUG_UI) --command=$(GDBINIT_FILE)




# Create final output files (.hex, .eep) from ELF output file.
%.hex: %.elf
	@$(ECHO_BLANK)
	@echo $(MSG_FLASH) $@
	$(OBJCOPY) -O ihex -R .eeprom -R .fuse -R .lock -R .signature $< $@

%.bin: %.elf
	@$(ECHO_BLANK)
	@echo $(MSG_FLASH) $@
	$(OBJCOPY) -O binary -R .eeprom -R .fuse -R .lock -R .signature $< $@


%.eep: %.elf
	@$(ECHO_BLANK)
	@echo $(MSG_EEPROM) $@
	-$(OBJCOPY) -j .eeprom --set-section-flags=.eeprom="alloc,load" \
	--change-section-lma .eeprom=0 --no-change-warnings -O ihex $< $@ || exit 0

# Create extended listing file from ELF output file.
%.lss: %.elf
	@$(ECHO_BLANK)
	@echo $(MSG_EXTENDED_LISTING) $@
	$(OBJDUMP) -h -S -z $< > $@

# Create a symbol table from ELF output file.
%.sym: %.elf
	@$(ECHO_BLANK)
	@echo $(MSG_SYMBOL_TABLE) $@
	$(NM) -n $< > $@

# Create library from object files.
.SECONDARY : $(TARGET-PLAT).a
.PRECIOUS : $(OBJ)
%.a: $(OBJ)
	@$(ECHO_BLANK)
	@echo $(MSG_CREATING_LIBRARY) $@
	$(AR) $@ $(OBJ)

# Link: create ELF output file from object files.
.SECONDARY : $(TARGET-PLAT).elf
.PRECIOUS : $(OBJ)
%.elf: $(OBJ)
	@$(ECHO_BLANK)
	@echo LINKING:
	@echo -en $(LINKMSG)
	@$(LINK_COMPILER) $(ALL_CFLAGS) $^ --output $@ $(LDFLAGS)
	@echo -e $(DONEMSG)

# Compile: create object files from C source files.
$(OBJDIR)/%.o : %.c
	@$(ECHO_BLANK)
	@echo Compiling:
	@echo -en $(COMPMSG)
	@$(CC) -c $(ALL_CFLAGS) $< -o $@
	@echo -e $(DONEMSG)

# Compile: create object files from C++ source files.
$(OBJDIR)/%.o : %.cpp
	@$(ECHO_BLANK)
	@echo Compiling C++:
	@echo -en $(COMPCPPMSG)
	@$(CXX) -c $(ALL_CFLAGS) $< -o $@
	@echo -e $(DONEMSG)

# Compile: create assembler files from C source files.
%.s : %.c
	$(CC) -S $(ALL_CFLAGS) $< -o $@

# Compile: create assembler files from C++ source files.
%.s : %.cpp
	$(CC) -S $(ALL_CPPFLAGS) $< -o $@

# Assemble: create object files from assembler source files.
$(OBJDIR)/%.o : %.S
	@$(ECHO_BLANK)
	@echo $(MSG_ASSEMBLING) $<
	$(CC) -c $(ALL_ASFLAGS) $< -o $@

# Create preprocessed source for use in sending a bug report.
%.i : %.c
	$(CC) -E $(MCU_FLAGS) -I. $(CFLAGS) $< -o $@

# Clean all object files specific to this platform
clean_objs :
	@$(REMOVE) $(TARGET-PLAT).hex
	@$(REMOVE) $(TARGET-PLAT).eep
	@$(REMOVE) $(TARGET-PLAT).bin
	@$(REMOVE) $(TARGET-PLAT).cof
	@$(REMOVE) $(TARGET-PLAT).elf
	@$(REMOVE) $(TARGET-PLAT).map
	@$(REMOVE) $(TARGET-PLAT).sym
	@$(REMOVE) $(TARGET-PLAT).lss
	@$(REMOVE) $(TARGET-PLAT).json
	@$(REMOVE) $(OBJDIR)/*.o
	@$(REMOVE) $(OBJDIR)/*.lst
	$(REMOVEDIR) $(OBJDIR)
	@$(REMOVE) $(SRC:.c=.s)
	@$(REMOVE) $(SRC:.c=.d)
	@$(REMOVE) $(SRC:.c=.i)

# Target: clean project.
clean: clean_print clean_objs clean_list

clean_print :
	@$(ECHO_BLANK)
	@echo $(MSG_CLEANING)

# Clean all object files related to any of the platforms
clean_all_objs :
	$(REMOVE) $(addsuffix .hex,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .eep,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .bin,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .cof,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .elf,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .map,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .sym,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .lss,$(TARGET-ALL))
	$(REMOVE) $(addsuffix .json,$(TARGET-ALL))
	$(REMOVE) $(OBJDIR)/*.o
	$(REMOVE) $(OBJDIR)/*.lst
	$(REMOVEDIR) $(OBJDIR)
	$(REMOVE) $(SRC:.c=.s)
	$(REMOVE) $(SRC:.c=.d)
	$(REMOVE) $(SRC:.c=.i)

clean_list :
	$(REMOVEDIR) .dep

# Create object files directory
#$(shell mkdir $(OBJDIR) 2>/dev/null)

# Include the dependency files.
#-include $(shell mkdir .dep 2>/dev/null) $(wildcard .dep/*)
-include $(wildcard .dep/*)

all: 
	clean_objs .dep gccversion build create_config sizeafter fastnote end

# Listing of phony targets.
.PHONY : all allquick begin finish create_config end sizeafter gccversion \
build elf hex bin eep lss sym coff extcoff help\
clean clean_list clean_print clean_objs program debug gdb-config \
fastnote

# saveplatform: Save the platform into the file Makefile.target
saveplatform:
	-@rm -f Makefile.platform
	@echo "Saving Makefile.platform"
	@echo >Makefile.platform "PLATFORM = $(PLATFORM)"
