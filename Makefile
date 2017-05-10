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

3RDPARTY    =  $(SRCDIR)/3rd_party
BASEDIR     =  $(SRCDIR)/base
NAMESDIR    =  $(SRCDIR)/names
PRAGMADIR   =  $(SRCDIR)/pragmatics
UTILSDIR    =  $(SRCDIR)/utils
ENCSDIR     =  $(SRCDIR)/encoders
DIGDIR      =  $(SRCDIR)/digests
RNDDIR      =  $(SRCDIR)/random
CIPHDIR     =  $(SRCDIR)/ciphers
UTILITYDIR  =  $(SRCDIR)/utility
FACTDIR     =  $(SRCDIR)/factories

#>>>[Compilation]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

ADACC       =  gnatmake -c
SOURCEDIRS  =  -I$(3RDPARTY)/ -I$(BASEDIR)/ -I$(UTILSDIR)/ -I$(NAMESDIR)/ -I$(PRAGMADIR)/ -I$(ENCSDIR)/ -I$(DIGDIR)/ -I$(RNDDIR)/ -I$(BNDIR)/ -I$(CIPHDIR)/ -I$(FACTDIR)/
CFLAGS      =  $(SOURCEDIRS) -D $(OBJDIR) -O3 -gnat05 -gnata -gnatn -gnatwa
ADAMAKER    = gnatmake
ADAFLAGS    = -O3 -gnat05 -gnata -gnatn -gnatwa -D $(OBJDIR)

#>>>[Delete command]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#DELCMD = del
#DELCMD = del /Q
DELCMD = rm -f

#>>>[Objects]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

OBJS     =  cryptada.o \
            cryptada-identification.o \
            cryptada-exceptions.o \
            cryptada-lists.o \
            cryptada-lists-identifier_item.o \
            cryptada-lists-enumeration_item.o \
            cryptada-lists-integer_item.o \
            cryptada-lists-float_item.o \
            cryptada-lists-string_item.o \
            cryptada-lists-list_item.o \
            cryptada-ref_counters.o \
            cryptada-names.o \
            cryptada-names-asn1_oids.o \
            cryptada-names-scan.o \
            cryptada-names-openpgp.o \
            cryptada-pragmatics.o \
            cryptada-pragmatics-byte_vectors.o \
            cryptada-utils.o \
            cryptada-utils-format.o \
            cryptada-text_encoders.o \
            cryptada-text_encoders-hex.o \
            cryptada-text_encoders-base16.o \
            cryptada-text_encoders-base64.o \
            cryptada-text_encoders-base64-mime.o \
            cryptada-digests.o \
            cryptada-digests-hashes.o \
            cryptada-digests-counters.o \
            cryptada-digests-algorithms.o \
            cryptada-digests-algorithms-md2.o \
            cryptada-digests-algorithms-md4.o \
            cryptada-digests-algorithms-md5.o \
            cryptada-digests-algorithms-ripemd_128.o \
            cryptada-digests-algorithms-ripemd_160.o \
            cryptada-digests-algorithms-sha_1.o \
            cryptada-digests-algorithms-sha_224.o \
            cryptada-digests-algorithms-sha_256.o \
            cryptada-digests-algorithms-sha_384.o \
            cryptada-digests-algorithms-sha_512.o \
            cryptada-digests-algorithms-sha_3.o \
            cryptada-digests-algorithms-snefru.o \
            cryptada-digests-algorithms-tiger.o \
            cryptada-digests-algorithms-haval.o \
            cryptada-digests-algorithms-whirlpool.o \
            cryptada-random.o \
            cryptada-random-generators.o \
            cryptada-random-generators-rsaref.o \
            cryptada-random-generators-caprng.o \
            cryptada-ciphers.o \
            cryptada-ciphers-keys.o \
            cryptada-ciphers-symmetric.o \
            cryptada-ciphers-symmetric-block.o \
            cryptada-ciphers-symmetric-block-des.o \
            cryptada-ciphers-symmetric-block-desx.o \
            cryptada-ciphers-symmetric-block-des2x.o \
            cryptada-ciphers-symmetric-block-tdea.o \
            cryptada-ciphers-symmetric-block-blowfish.o \
            cryptada-ciphers-symmetric-block-aes.o \
            cryptada-ciphers-symmetric-block-rc2.o \
            cryptada-ciphers-symmetric-block-idea.o \
            cryptada-ciphers-symmetric-block-cast_128.o \
            cryptada-ciphers-symmetric-block-twofish.o \
            cryptada-ciphers-symmetric-stream.o \
            cryptada-ciphers-symmetric-stream-rc4.o \
            cryptada-ciphers-key_generators.o \
            cryptada-ciphers-key_generators-tdea.o \
            cryptada-factories.o \
            cryptada-factories-text_encoder_factory.o

UTILITY  =  $(BINDIR)/gen_twofish_mds.exe


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

cryptada-ref_counters.o: $(BASEDIR)/cryptada-ref_counters.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-lists.o: $(BASEDIR)/cryptada-lists.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-lists-identifier_item.o: $(BASEDIR)/cryptada-lists-identifier_item.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-lists-enumeration_item.o: $(BASEDIR)/cryptada-lists-enumeration_item.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-lists-integer_item.o: $(BASEDIR)/cryptada-lists-integer_item.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-lists-float_item.o: $(BASEDIR)/cryptada-lists-float_item.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-lists-string_item.o: $(BASEDIR)/cryptada-lists-string_item.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-lists-list_item.o: $(BASEDIR)/cryptada-lists-list_item.adb
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

cryptada-text_encoders.o: $(ENCSDIR)/cryptada-text_encoders.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-text_encoders-hex.o: $(ENCSDIR)/cryptada-text_encoders-hex.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-text_encoders-base16.o: $(ENCSDIR)/cryptada-text_encoders-base16.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<
    
cryptada-text_encoders-base64.o: $(ENCSDIR)/cryptada-text_encoders-base64.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-text_encoders-base64-mime.o: $(ENCSDIR)/cryptada-text_encoders-base64-mime.adb
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

cryptada-digests-algorithms-md4.o: $(DIGDIR)/cryptada-digests-algorithms-md4.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-md5.o: $(DIGDIR)/cryptada-digests-algorithms-md5.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-ripemd_128.o: $(DIGDIR)/cryptada-digests-algorithms-ripemd_128.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-ripemd_160.o: $(DIGDIR)/cryptada-digests-algorithms-ripemd_160.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-sha_1.o: $(DIGDIR)/cryptada-digests-algorithms-sha_1.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-sha_224.o: $(DIGDIR)/cryptada-digests-algorithms-sha_224.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-sha_256.o: $(DIGDIR)/cryptada-digests-algorithms-sha_256.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-sha_384.o: $(DIGDIR)/cryptada-digests-algorithms-sha_384.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-sha_512.o: $(DIGDIR)/cryptada-digests-algorithms-sha_512.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-sha_3.o: $(DIGDIR)/cryptada-digests-algorithms-sha_3.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-snefru.o: $(DIGDIR)/cryptada-digests-algorithms-snefru.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-tiger.o: $(DIGDIR)/cryptada-digests-algorithms-tiger.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-haval.o: $(DIGDIR)/cryptada-digests-algorithms-haval.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-digests-algorithms-whirlpool.o: $(DIGDIR)/cryptada-digests-algorithms-whirlpool.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

# Random packages

cryptada-random.o: $(RNDDIR)/cryptada-random.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-random-generators.o: $(RNDDIR)/cryptada-random-generators.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-random-generators-rsaref.o: $(RNDDIR)/cryptada-random-generators-rsaref.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-random-generators-caprng.o: $(RNDDIR)/cryptada-random-generators-caprng.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

# Ciphers pakages

cryptada-ciphers.o: $(CIPHDIR)/cryptada-ciphers.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-keys.o: $(CIPHDIR)/cryptada-ciphers-keys.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric.o: $(CIPHDIR)/cryptada-ciphers-symmetric.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-des.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-des.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-desx.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-desx.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-des2x.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-des2x.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-tdea.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-tdea.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-blowfish.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-blowfish.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-aes.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-aes.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-rc2.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-rc2.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-idea.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-idea.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-cast_128.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-cast_128.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-block-twofish.o: $(CIPHDIR)/cryptada-ciphers-symmetric-block-twofish.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<
    
cryptada-ciphers-symmetric-stream.o: $(CIPHDIR)/cryptada-ciphers-symmetric-stream.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-symmetric-stream-rc4.o: $(CIPHDIR)/cryptada-ciphers-symmetric-stream-rc4.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-key_generators.o: $(CIPHDIR)/cryptada-ciphers-key_generators.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-ciphers-key_generators-tdea.o: $(CIPHDIR)/cryptada-ciphers-key_generators-tdea.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

# Factories pakages

cryptada-factories.o: $(FACTDIR)/cryptada-factories.ads
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<

cryptada-factories-text_encoder_factory.o: $(FACTDIR)/cryptada-factories-text_encoder_factory.adb
	@echo Compiling $<
	$(ADACC) $(CFLAGS) $<
    
# Utility tools

$(BINDIR)/gen_twofish_mds.exe: $(UTILITYDIR)/gen_twofish_mds.adb
	@echo Building $<
	$(ADAMAKER) $(SOURCEDIRS) $(ADAFLAGS) -o $@ $<

#>>>[Targets]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

all: objs utility

objs: $(OBJS)

utility: $(UTILITY)

clean:
	$(DELCMD) $(OBJDIR)/*.o
	$(DELCMD) $(OBJDIR)/*.ali
	$(DELCMD) $(BINDIR)/*.exe

