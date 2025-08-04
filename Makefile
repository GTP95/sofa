# Starting Makefile for ArmChair program
#----------------------------------------------------------------------------
# On command line:
#
# make TARGET={PROFILE_FOLDER} - Make software targeting the algorithm profile in the folder.
#
# make clean TARGET={PROFILE_FOLDER}  - Clean out built project files for that profile.
#
# make help TARGET={PROFILE_FOLDER}   - Get settings for that profile.
#
# To rebuild project do "make clean" then "make" with the correct target again.
#----------------------------------------------------------------------------
# Ideally don't modify this as the whole project has a pretty specific structure!
# That being said, do if you know what you are doing ;)
include ./Makefile.settings
include $(TARGETSPATH)/Makefile.targets
include $(FIRMWAREPATH)/Makefile.inc