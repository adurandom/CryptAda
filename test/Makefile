################################################################################
#                        (c) 2017, TCantos Software                            #
#                             aduran@tcantos.com                               #
################################################################################
# This  program  is free  software: you  can redistribute it and/or  modify it #
# under the terms  of  the GNU General Public License as published by the Free #
# Software Foundation,  either  version  3 of the License, or (at your option) #
# any later version.                                                           #
#                                                                              #
# This program is distributed in the hope that it will be useful,  but WITHOUT #
# ANY WARRANTY;  without  even  the  implied warranty  of  MERCHANTABILITY  or #
# FITNESS  FOR  A  PARTICULAR PURPOSE.  See the GNU General Public License for #
# more details.                                                                #
#                                                                              #
# You should have received a copy of the GNU General Public License along with #
# this program. If not, see <http://www.gnu.org/licenses/>.                    #
################################################################################
# Filename       : Makefile
# Author         : ADD
# Creaton date   : February 11th, 2017
# Current version: 1.0
# Purpose        : Makefile for testing AdaCrypt library.
#
# Ver   Date     Author          Reason
# ----- -------- --------------- -----------------------------------------------
#   1.0 20170211 ADD             Initial implementation.
################################################################################

#>>>[Directories]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

ACSRC       =  ../src
ACOBJ       =  ../obj
ACLIB       =  ../lib
TSRC        =  ./src
TOBJ        =  ./obj
TBIN        =  ./bin
TRES        =  ./res

ACBASE      =  $(ACSRC)/base
ACNAMES     =  $(ACSRC)/names
ACPRAGMA    =  $(ACSRC)/pragmatics
ACUTILS     =  $(ACSRC)/utils
ACENCODERS  =  $(ACSRC)/encoders
ACDIGESTS   =  $(ACSRC)/digests
ACRANDOM    =  $(ACSRC)/random

TSRCBASE    =  $(TSRC)/base/
TSRCUPKG    =  $(TSRC)/upkg/
TSRCUDRV    =  $(TSRC)/udrv/

#>>>[Compilation]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

CC          =  gcc
CFLAGS      =  -c -O3 -gnat05 -gnata -gnatn -gnatwa
SOURCEDIRS  =  -I$(TSRCBASE) -I$(TSRCUPKG) -I$(ACBASE) -I$(ACNAMES) -I$(ACPRAGMA) -I$(ACUTILS) -I$(ACENCODERS) -I$(ACDIGESTS) -I$(ACRANDOM)

ADAMAKER    = gnatmake
ADAFLAGS    = -O3 -gnatn -gnatwa -D $(TOBJ)

#>>>[Ada Body Extension]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

adb         = .adb

#>>>[Delete command]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#DELCMD = del
#DELCMD = del /Q
DELCMD = rm -f

#>>>[Objects]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

UNITDRV  =  $(TBIN)/ut_utils.exe \
            $(TBIN)/ut_pragmatics.exe \
            $(TBIN)/ut_bvectors.exe \
            
#>>>[Build Rules]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

.PHONY: all unit time clean run

#>>>[Building Unit Test Drivers]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

$(TBIN)/ut_utils.exe: $(TSRCUDRV)ut_utils.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_pragmatics.exe: $(TSRCUDRV)ut_pragmatics.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_bvectors.exe: $(TSRCUDRV)ut_bvectors.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<
    
#>>>[Targets]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

all: unit time

unit: $(UNITDRV)

time: $(TIMEDRV)

clean:
	$(DELCMD) $(TOBJ)/*.o
	$(DELCMD) $(TOBJ)/*.ali
	$(DELCMD) $(TBIN)/*.exe
	$(DELCMD) $(TRES)/*.txt

run: run_unit run_time

run_unit: $(UNITDRV)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running test driver: $$testdriver ... ; \
		$(TBIN)/$$testdriver.exe > $(TRES)/$$testdriver.txt ;\
	done

run_time: $(TIMEDRV)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running test driver: $$testdriver ... ; \
		$(TBIN)/$$testdriver.exe > $(TRES)/$$testdriver.txt ;\
	done
