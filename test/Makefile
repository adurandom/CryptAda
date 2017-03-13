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
# Purpose        : Makefile for testing CryptAda library.
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
            $(TBIN)/ut_hexenc.exe \
            $(TBIN)/ut_b16enc.exe \
            $(TBIN)/ut_b64enc.exe \
            $(TBIN)/ut_mimeenc.exe \
            $(TBIN)/ut_count.exe \
            $(TBIN)/ut_md2.exe \
            $(TBIN)/ut_md4.exe \
            $(TBIN)/ut_md5.exe \
            $(TBIN)/ut_ripemd_128.exe \
            $(TBIN)/ut_ripemd_160.exe \
            $(TBIN)/ut_sha_1.exe \
            $(TBIN)/ut_sha_224.exe \
            $(TBIN)/ut_sha_256.exe \
            $(TBIN)/ut_sha_384.exe \
            $(TBIN)/ut_sha_512.exe
            
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

$(TBIN)/ut_hexenc.exe: $(TSRCUDRV)ut_hexenc.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_b16enc.exe: $(TSRCUDRV)ut_b16enc.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_b64enc.exe: $(TSRCUDRV)ut_b64enc.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_mimeenc.exe: $(TSRCUDRV)ut_mimeenc.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_count.exe: $(TSRCUDRV)ut_count.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_md2.exe: $(TSRCUDRV)ut_md2.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_md4.exe: $(TSRCUDRV)ut_md4.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_md5.exe: $(TSRCUDRV)ut_md5.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_ripemd_128.exe: $(TSRCUDRV)ut_ripemd_128.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_ripemd_160.exe: $(TSRCUDRV)ut_ripemd_160.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_sha_1.exe: $(TSRCUDRV)ut_sha_1.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_sha_224.exe: $(TSRCUDRV)ut_sha_224.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_sha_256.exe: $(TSRCUDRV)ut_sha_256.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_sha_384.exe: $(TSRCUDRV)ut_sha_384.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

$(TBIN)/ut_sha_512.exe: $(TSRCUDRV)ut_sha_512.adb
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
