# Starting Makefile for ArmChair program
#----------------------------------------------------------------------------
# On command line:
#
# make TARGET={PROFILE_FOLDER} - Make software targeting the algorithm profile in the folder.
#
# make clean                          - Clean out built files for all bundled examples.
# make clean TARGET={PROFILE_FOLDER}  - Clean out built project files for that profile.
#
# make help TARGET={PROFILE_FOLDER}   - Get settings for that profile.
#
# To rebuild project do "make clean" then "make" with the correct target again.
#----------------------------------------------------------------------------
# Ideally don't modify this as the whole project has a pretty specific structure!
# That being said, do if you know what you are doing ;)
# A bare clean cannot include the regular build configuration because that
# configuration intentionally requires TARGET. Dispatch to the existing
# target-specific clean recipe for every bundled example instead.
BUNDLED_TARGETS := $(notdir $(patsubst %/,%,$(wildcard ./Targets/*/)))
CLEAN_ALL := $(if $(filter clean,$(MAKECMDGOALS)),$(if $(strip $(TARGET)),,1))

ifeq ($(CLEAN_ALL),1)
.PHONY: clean
clean:
	@set -e; for target in $(BUNDLED_TARGETS); do \
		$(MAKE) --no-print-directory TARGET=$$target clean; \
	done
else
include ./Makefile.settings
include $(TARGETSPATH)/Makefile.targets
include $(FIRMWAREPATH)/Makefile.inc
endif
