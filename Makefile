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
# Creaton date   : March 13th, 2017
# Current version: 1.0
# Purpose        : Makefile for CryptAda library.
#
# Ver   Date     Author          Reason
# ----- -------- --------------- -----------------------------------------------
#   1.0 20170313 ADD             Initial implementation.
################################################################################

#>>>[Directories]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

SRCDIR      =  src
OBJDIR      =  ./obj
LIBDIR      =  ./lib
BINDIR      =  ./bin

BASEDIR     =  $(SRCDIR)/base
NAMESDIR    =  $(SRCDIR)/names
PRAGMADIR   =  $(SRCDIR)/pragmatics
UTILSDIR    =  $(SRCDIR)/utils
ENCSDIR     =  $(SRCDIR)/encoders
DIGDIR      =  $(SRCDIR)/digests

#>>>[Compilation]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

ADACC       =  gnatmake -c 
SOURCEDIRS  =  -I$(BASEDIR)/ -I$(NAMESDIR)/ -I$(PRAGMADIR)/ -I$(ENCSDIR)/ -I$(DIGDIR)/
CFLAGS      =  $(SOURCEDIRS) -D $(OBJDIR) -O3 -gnat05 -gnata -gnatn -gnatwa

#>>>[Delete command]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#DELCMD = del
#DELCMD = del /Q
DELCMD = rm -f

#>>>[Objects]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

OBJS     =  cryptada.o \
            cryptada-identification.o \
            cryptada-exceptions.o \
            cryptada-names.o \
            cryptada-names-asn1_oids.o \
            cryptada-names-scan.o \
            cryptada-names-openpgp.o \
            cryptada-pragmatics.o \
            cryptada-pragmatics-byte_vectors.o \
            cryptada-utils.o \
            cryptada-utils-format.o \
            cryptada-encoders.o \
            cryptada-encoders-hex_encoders.o \
            cryptada-encoders-base16_encoders.o \
            cryptada-encoders-base64_encoders.o \
            cryptada-encoders-base64_encoders-mime_encoders.o \
            cryptada-digests.o \
            cryptada-digests-hashes.o \
            cryptada-digests-counters.o \
            cryptada-digests-algorithms.o \
            cryptada-digests-algorithms-md2.o

#>>>[Build Rules]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

.PHONY: all objs clean

#>>>[Compile]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Base packages

cryptada.o: $(BASEDIR)/cryptada.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $< 

cryptada-identification.o: $(BASEDIR)/cryptada-identification.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $< 

cryptada-exceptions.o: $(BASEDIR)/cryptada-exceptions.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $< 

# Names packages

cryptada-names.o: $(NAMESDIR)/cryptada-names.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-names-asn1_oids.o: $(NAMESDIR)/cryptada-names-asn1_oids.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $< 

cryptada-names-scan.o: $(NAMESDIR)/cryptada-names-scan.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $< 

cryptada-names-openpgp.o: $(NAMESDIR)/cryptada-names-openpgp.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $< 

# Pragmatics packages

cryptada-pragmatics.o: $(PRAGMADIR)/cryptada-pragmatics.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-pragmatics-byte_vectors.o: $(PRAGMADIR)/cryptada-pragmatics-byte_vectors.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

# Utils packages

cryptada-utils.o: $(UTILSDIR)/cryptada-utils.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-utils-format.o: $(UTILSDIR)/cryptada-utils-format.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

# Encoders packages

cryptada-encoders.o: $(ENCSDIR)/cryptada-encoders.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-encoders-hex_encoders.o: $(ENCSDIR)/cryptada-encoders-hex_encoders.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-encoders-base16_encoders.o: $(ENCSDIR)/cryptada-encoders-base16_encoders.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-encoders-base64_encoders.o: $(ENCSDIR)/cryptada-encoders-base64_encoders.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-encoders-base64_encoders-mime_encoders.o: $(ENCSDIR)/cryptada-encoders-base64_encoders-mime_encoders.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

# Digests packages

cryptada-digests.o: $(DIGDIR)/cryptada-digests.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-hashes.o: $(DIGDIR)/cryptada-digests-hashes.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-counters.o: $(DIGDIR)/cryptada-digests-counters.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms.o: $(DIGDIR)/cryptada-digests-algorithms.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-md2.o: $(DIGDIR)/cryptada-digests-algorithms-md2.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<
    
#>>>[Targets]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

all: objs

objs: $(OBJS)

clean:
	$(DELCMD) $(OBJDIR)/*.o
	$(DELCMD) $(OBJDIR)/*.ali

