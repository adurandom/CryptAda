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

# CryptAda root directories (CA_)

CA_SRC          =  ../src
CA_OBJ          =  ../obj
CA_LIB          =  ../lib

# CryptAda Test root directories (CT_)

CT_SRC          =  ./src
CT_OBJ          =  ./obj
CT_BIN          =  ./bin
CT_RES          =  ./res

# CryptAda source directories (CAS_)

CAS_3PARTY      =  $(CA_SRC)/3rd_party
CAS_BASE        =  $(CA_SRC)/base
CAS_NAMES       =  $(CA_SRC)/names
CAS_PRAGMA      =  $(CA_SRC)/pragmatics
CAS_UTILS       =  $(CA_SRC)/utils
CAS_ENCODERS    =  $(CA_SRC)/encoders
CAS_DIGESTS     =  $(CA_SRC)/digests
CAS_RANDOM      =  $(CA_SRC)/random
CAS_CIPHERS     =  $(CA_SRC)/ciphers
CAS_FACTORIES   =  $(CA_SRC)/factories

# CryptAda test source directories CTS_

CTS_BASE        =  $(CT_SRC)/base/
CTS_UTILS       =  $(CT_SRC)/utils/

CTS_UUT_PKG     =  $(CT_SRC)/uut_pkg/
CTS_UUT_DRV     =  $(CT_SRC)/uut_drv/
CTS_UPR_PKG     =  $(CT_SRC)/upr_pkg/
CTS_UPR_DRV     =  $(CT_SRC)/upr_drv/
CTS_UEN_PKG     =  $(CT_SRC)/uen_pkg/
CTS_UEN_DRV     =  $(CT_SRC)/uen_drv/
CTS_UDI_PKG     =  $(CT_SRC)/udi_pkg/
CTS_UDI_DRV     =  $(CT_SRC)/udi_drv/
CTS_URN_PKG     =  $(CT_SRC)/urn_pkg/
CTS_URN_DRV     =  $(CT_SRC)/urn_drv/
CTS_UBC_PKG     =  $(CT_SRC)/ubc_pkg/
CTS_UBC_DRV     =  $(CT_SRC)/ubc_drv/

CTS_TDI_PKG     =  $(CT_SRC)/tdi_pkg/
CTS_TDI_DRV     =  $(CT_SRC)/tdi_drv/

#  CryptAda test bin directories (CTB_)

CTB_UUTILS      = $(CT_BIN)/u_utils
CTB_UPRAG       = $(CT_BIN)/u_prag
CTB_UENC        = $(CT_BIN)/u_enc
CTB_UDIG        = $(CT_BIN)/u_dig
CTB_URND        = $(CT_BIN)/u_rnd
CTB_UBC         = $(CT_BIN)/u_bc

CTB_TDIG        = $(CT_BIN)/t_dig

#>>>[Compilation]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

ADAMAKER    = gnatmake
ADAFLAGS    = -O3 -gnat05 -gnata -gnatn -gnatwa -D $(CT_OBJ)

IDIR_UUT    = -I$(CTS_BASE) -I$(CTS_UTILS) -I$(CTS_UUT_PKG) -I$(CAS_3PARTY) -I$(CAS_BASE) -I$(CAS_NAMES) -I$(CAS_PRAGMA) -I$(CAS_UTILS)
IDIR_UPR    = -I$(CTS_BASE) -I$(CTS_UTILS) -I$(CTS_UPR_PKG) -I$(CAS_3PARTY) -I$(CAS_BASE) -I$(CAS_NAMES) -I$(CAS_PRAGMA) -I$(CAS_UTILS)
IDIR_UEN    = -I$(CTS_BASE) -I$(CTS_UTILS) -I$(CTS_UEN_PKG) -I$(CAS_3PARTY) -I$(CAS_BASE) -I$(CAS_NAMES) -I$(CAS_PRAGMA) -I$(CAS_UTILS) -I$(CAS_ENCODERS) -I$(CAS_FACTORIES)
IDIR_UDI    = -I$(CTS_BASE) -I$(CTS_UTILS) -I$(CTS_UDI_PKG) -I$(CAS_3PARTY) -I$(CAS_BASE) -I$(CAS_NAMES) -I$(CAS_PRAGMA) -I$(CAS_UTILS) -I$(CAS_ENCODERS) -I$(CAS_FACTORIES) -I$(CAS_DIGESTS)
IDIR_URN    = -I$(CTS_BASE) -I$(CTS_UTILS) -I$(CTS_URN_PKG) -I$(CAS_3PARTY) -I$(CAS_BASE) -I$(CAS_NAMES) -I$(CAS_PRAGMA) -I$(CAS_UTILS) -I$(CAS_ENCODERS) -I$(CAS_FACTORIES) -I$(CAS_DIGESTS) -I$(CAS_RANDOM)
IDIR_UBC    = -I$(CTS_BASE) -I$(CTS_UTILS) -I$(CTS_UBC_PKG) -I$(CAS_3PARTY) -I$(CAS_BASE) -I$(CAS_NAMES) -I$(CAS_PRAGMA) -I$(CAS_UTILS) -I$(CAS_ENCODERS) -I$(CAS_FACTORIES) -I$(CAS_DIGESTS) -I$(CAS_RANDOM) -I$(CAS_CIPHERS)

IDIR_TDI    = -I$(CTS_BASE) -I$(CTS_UTILS) -I$(CTS_TDI_PKG) -I$(CAS_3PARTY) -I$(CAS_BASE) -I$(CAS_NAMES) -I$(CAS_PRAGMA) -I$(CAS_UTILS) -I$(CAS_ENCODERS) -I$(CAS_FACTORIES) -I$(CAS_DIGESTS)

#>>>[Delete command]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#DELCMD = del
#DELCMD = del /Q
DELCMD = rm -f

#>>>[Objects]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

U_UTILS     =   $(CTB_UUTILS)/ut_utils.exe \
                $(CTB_UUTILS)/ut_format.exe \
                $(CTB_UUTILS)/ut_lists.exe \
                $(CTB_UUTILS)/ut_lists_ids.exe \
                $(CTB_UUTILS)/ut_lists_enums.exe \
                $(CTB_UUTILS)/ut_lists_integers.exe \
                $(CTB_UUTILS)/ut_lists_floats.exe \
                $(CTB_UUTILS)/ut_lists_strings.exe \
                $(CTB_UUTILS)/ut_lists_lists.exe 

U_PRAG      =   $(CTB_UPRAG)/ut_pragmatics.exe \
                $(CTB_UPRAG)/ut_bvectors.exe

U_ENC       =   $(CTB_UENC)/ut_enc_hex.exe \
                $(CTB_UENC)/ut_enc_base16.exe \
                $(CTB_UENC)/ut_enc_base64.exe \
                $(CTB_UENC)/ut_enc_mime.exe \
                $(CTB_UENC)/ut_enc_factory.exe 
                

U_DIG       =   $(CTB_UDIG)/ut_count.exe \
                $(CTB_UDIG)/ut_hashes.exe \
                $(CTB_UDIG)/ut_md_md2.exe \
                $(CTB_UDIG)/ut_md_md4.exe \
                $(CTB_UDIG)/ut_md_md5.exe \
                $(CTB_UDIG)/ut_md_ripemd_128.exe \
                $(CTB_UDIG)/ut_md_ripemd_160.exe \
                $(CTB_UDIG)/ut_md_ripemd_256.exe \
                $(CTB_UDIG)/ut_md_ripemd_320.exe \
                $(CTB_UDIG)/ut_md_snefru.exe \
                $(CTB_UDIG)/ut_md_sha_1.exe \
                $(CTB_UDIG)/ut_md_blake_224.exe \
                $(CTB_UDIG)/ut_md2.exe \
                $(CTB_UDIG)/ut_md4.exe \
                $(CTB_UDIG)/ut_md5.exe \
                $(CTB_UDIG)/ut_ripemd_128.exe \
                $(CTB_UDIG)/ut_ripemd_160.exe \
                $(CTB_UDIG)/ut_sha_1.exe \
                $(CTB_UDIG)/ut_sha_224.exe \
                $(CTB_UDIG)/ut_sha_256.exe \
                $(CTB_UDIG)/ut_sha_384.exe \
                $(CTB_UDIG)/ut_sha_512.exe \
                $(CTB_UDIG)/ut_sha_3.exe \
                $(CTB_UDIG)/ut_snefru.exe \
                $(CTB_UDIG)/ut_tiger.exe \
                $(CTB_UDIG)/ut_haval.exe \
                $(CTB_UDIG)/ut_whirlpool.exe

U_RND       =   $(CTB_URND)/ut_rsaref.exe \
                $(CTB_URND)/ut_caprng.exe

U_BC        =   $(CTB_UBC)/ut_keys.exe \
                $(CTB_UBC)/ut_des.exe \
                $(CTB_UBC)/ut_desx.exe \
                $(CTB_UBC)/ut_des2x.exe \
                $(CTB_UBC)/ut_tdea.exe \
                $(CTB_UBC)/ut_aes.exe \
                $(CTB_UBC)/ut_blowfish.exe \
                $(CTB_UBC)/ut_rc2.exe \
                $(CTB_UBC)/ut_idea.exe \
                $(CTB_UBC)/ut_cast_128.exe \
                $(CTB_UBC)/ut_twofish.exe \
                $(CTB_UBC)/ut_rc4.exe \
                $(CTB_UBC)/ut_key_generators.exe \
                $(CTB_UBC)/ut_kg_tdea.exe
                
                
T_DIG       =   $(CTB_TDIG)/tt_md2.exe \
                $(CTB_TDIG)/tt_md4.exe \
                $(CTB_TDIG)/tt_md5.exe \
                $(CTB_TDIG)/tt_ripemd_128.exe \
                $(CTB_TDIG)/tt_ripemd_160.exe \
                $(CTB_TDIG)/tt_sha_1.exe \
                $(CTB_TDIG)/tt_sha_224.exe \
                $(CTB_TDIG)/tt_sha_256.exe \
                $(CTB_TDIG)/tt_sha_384.exe \
                $(CTB_TDIG)/tt_sha_512.exe \
                $(CTB_TDIG)/tt_sha_3.exe \
                $(CTB_TDIG)/tt_snefru.exe \
                $(CTB_TDIG)/tt_tiger.exe \
                $(CTB_TDIG)/tt_haval.exe \
                $(CTB_TDIG)/tt_whirlpool.exe
                                
#>>>[Build Rules]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

.PHONY: all unit time clean run

#>>>[Building Unit Test Drivers]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Utils unit test drivers.

$(CTB_UUTILS)/ut_utils.exe: $(CTS_UUT_DRV)ut_utils.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_format.exe: $(CTS_UUT_DRV)ut_format.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_lists.exe: $(CTS_UUT_DRV)ut_lists.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_lists_ids.exe: $(CTS_UUT_DRV)ut_lists_ids.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_lists_enums.exe: $(CTS_UUT_DRV)ut_lists_enums.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_lists_integers.exe: $(CTS_UUT_DRV)ut_lists_integers.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_lists_floats.exe: $(CTS_UUT_DRV)ut_lists_floats.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_lists_strings.exe: $(CTS_UUT_DRV)ut_lists_strings.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<

$(CTB_UUTILS)/ut_lists_lists.exe: $(CTS_UUT_DRV)ut_lists_lists.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UUT) $(ADAFLAGS) -o $@ $<
        
# Pragmatics unit test drivers.

$(CTB_UPRAG)/ut_pragmatics.exe: $(CTS_UPR_DRV)ut_pragmatics.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UPR) $(ADAFLAGS) -o $@ $<

$(CTB_UPRAG)/ut_bvectors.exe: $(CTS_UPR_DRV)ut_bvectors.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UPR) $(ADAFLAGS) -o $@ $<
    
# Encoders unit test drivers.

$(CTB_UENC)/ut_enc_hex.exe: $(CTS_UEN_DRV)ut_enc_hex.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UEN) $(ADAFLAGS) -o $@ $<

$(CTB_UENC)/ut_enc_base16.exe: $(CTS_UEN_DRV)ut_enc_base16.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UEN) $(ADAFLAGS) -o $@ $<

$(CTB_UENC)/ut_enc_base64.exe: $(CTS_UEN_DRV)ut_enc_base64.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UEN) $(ADAFLAGS) -o $@ $<

$(CTB_UENC)/ut_enc_mime.exe: $(CTS_UEN_DRV)ut_enc_mime.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UEN) $(ADAFLAGS) -o $@ $<

$(CTB_UENC)/ut_enc_factory.exe: $(CTS_UEN_DRV)ut_enc_factory.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UEN) $(ADAFLAGS) -o $@ $<
    
# Digests unit test drivers.

$(CTB_UDIG)/ut_count.exe: $(CTS_UDI_DRV)ut_count.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_hashes.exe: $(CTS_UDI_DRV)ut_hashes.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_md_md2.exe: $(CTS_UDI_DRV)ut_md_md2.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_md_md4.exe: $(CTS_UDI_DRV)ut_md_md4.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_md_md5.exe: $(CTS_UDI_DRV)ut_md_md5.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<
    
$(CTB_UDIG)/ut_md_ripemd_128.exe: $(CTS_UDI_DRV)ut_md_ripemd_128.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<
    
$(CTB_UDIG)/ut_md_ripemd_160.exe: $(CTS_UDI_DRV)ut_md_ripemd_160.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<
    
$(CTB_UDIG)/ut_md_ripemd_256.exe: $(CTS_UDI_DRV)ut_md_ripemd_256.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<
    
$(CTB_UDIG)/ut_md_ripemd_320.exe: $(CTS_UDI_DRV)ut_md_ripemd_320.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<
    
$(CTB_UDIG)/ut_md_sha_1.exe: $(CTS_UDI_DRV)ut_md_sha_1.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_md_snefru.exe: $(CTS_UDI_DRV)ut_md_snefru.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<
    
$(CTB_UDIG)/ut_md_blake_224.exe: $(CTS_UDI_DRV)ut_md_blake_224.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<
    
    
$(CTB_UDIG)/ut_md2.exe: $(CTS_UDI_DRV)ut_md2.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_md4.exe: $(CTS_UDI_DRV)ut_md4.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_md5.exe: $(CTS_UDI_DRV)ut_md5.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_ripemd_128.exe: $(CTS_UDI_DRV)ut_ripemd_128.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_ripemd_160.exe: $(CTS_UDI_DRV)ut_ripemd_160.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_sha_1.exe: $(CTS_UDI_DRV)ut_sha_1.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_sha_224.exe: $(CTS_UDI_DRV)ut_sha_224.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_sha_256.exe: $(CTS_UDI_DRV)ut_sha_256.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_sha_384.exe: $(CTS_UDI_DRV)ut_sha_384.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_sha_512.exe: $(CTS_UDI_DRV)ut_sha_512.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_sha_3.exe: $(CTS_UDI_DRV)ut_sha_3.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_snefru.exe: $(CTS_UDI_DRV)ut_snefru.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_tiger.exe: $(CTS_UDI_DRV)ut_tiger.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_haval.exe: $(CTS_UDI_DRV)ut_haval.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

$(CTB_UDIG)/ut_whirlpool.exe: $(CTS_UDI_DRV)ut_whirlpool.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UDI) $(ADAFLAGS) -o $@ $<

# Random unit test drivers

$(CTB_URND)/ut_rsaref.exe: $(CTS_URN_DRV)ut_rsaref.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_URN) $(ADAFLAGS) -o $@ $<

$(CTB_URND)/ut_caprng.exe: $(CTS_URN_DRV)ut_caprng.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_URN) $(ADAFLAGS) -o $@ $<

# Block_Ciphers unit test drivers

$(CTB_UBC)/ut_keys.exe: $(CTS_UBC_DRV)ut_keys.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_des.exe: $(CTS_UBC_DRV)ut_des.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_desx.exe: $(CTS_UBC_DRV)ut_desx.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_des2x.exe: $(CTS_UBC_DRV)ut_des2x.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<
    
$(CTB_UBC)/ut_tdea.exe: $(CTS_UBC_DRV)ut_tdea.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<
    
$(CTB_UBC)/ut_aes.exe: $(CTS_UBC_DRV)ut_aes.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_blowfish.exe: $(CTS_UBC_DRV)ut_blowfish.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_rc2.exe: $(CTS_UBC_DRV)ut_rc2.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_idea.exe: $(CTS_UBC_DRV)ut_idea.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_cast_128.exe: $(CTS_UBC_DRV)ut_cast_128.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_twofish.exe: $(CTS_UBC_DRV)ut_twofish.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<
    
$(CTB_UBC)/ut_rc4.exe: $(CTS_UBC_DRV)ut_rc4.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<
    
$(CTB_UBC)/ut_key_generators.exe: $(CTS_UBC_DRV)ut_key_generators.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<

$(CTB_UBC)/ut_kg_tdea.exe: $(CTS_UBC_DRV)ut_kg_tdea.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_UBC) $(ADAFLAGS) -o $@ $<
    
#>>>[Building time trials Drivers]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Digests time trials

$(CTB_TDIG)/tt_md2.exe: $(CTS_TDI_DRV)tt_md2.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_md4.exe: $(CTS_TDI_DRV)tt_md4.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_md5.exe: $(CTS_TDI_DRV)tt_md5.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_ripemd_128.exe: $(CTS_TDI_DRV)tt_ripemd_128.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_ripemd_160.exe: $(CTS_TDI_DRV)tt_ripemd_160.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_sha_1.exe: $(CTS_TDI_DRV)tt_sha_1.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_sha_224.exe: $(CTS_TDI_DRV)tt_sha_224.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_sha_256.exe: $(CTS_TDI_DRV)tt_sha_256.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_sha_384.exe: $(CTS_TDI_DRV)tt_sha_384.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_sha_512.exe: $(CTS_TDI_DRV)tt_sha_512.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_sha_3.exe: $(CTS_TDI_DRV)tt_sha_3.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_snefru.exe: $(CTS_TDI_DRV)tt_snefru.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_tiger.exe: $(CTS_TDI_DRV)tt_tiger.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_haval.exe: $(CTS_TDI_DRV)tt_haval.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<

$(CTB_TDIG)/tt_whirlpool.exe: $(CTS_TDI_DRV)tt_whirlpool.adb
	@echo Building $<
	$(ADAMAKER) $(IDIR_TDI) $(ADAFLAGS) -o $@ $<
    
#>>>[Targets]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

all: unit time

unit: $(U_UTILS) $(U_PRAG) $(U_ENC) $(U_DIG) $(U_RND) $(U_BC)

time: $(T_DIG)

clean:
	$(DELCMD) $(CT_OBJ)/*.o
	$(DELCMD) $(CT_OBJ)/*.ali
	$(DELCMD) $(CT_RES)/*.txt
	$(DELCMD) $(CTB_UUTILS)/*.exe
	$(DELCMD) $(CTB_UPRAG)/*.exe
	$(DELCMD) $(CTB_UENC)/*.exe
	$(DELCMD) $(CTB_UDIG)/*.exe
	$(DELCMD) $(CTB_URND)/*.exe
	$(DELCMD) $(CTB_UBC)/*.exe
	$(DELCMD) $(CTB_TDIG)/*.exe

run: r_unit r_time

r_unit: r_utils r_prag r_enc r_dig r_rnd r_bc

r_utils: $(U_UTILS)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running utils test driver: $$testdriver ... ; \
		$(CTB_UUTILS)/$$testdriver.exe > $(CT_RES)/$$testdriver.txt ;\
	done

r_prag: $(U_PRAG)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running pragmatics test driver: $$testdriver ... ; \
		$(CTB_UPRAG)/$$testdriver.exe > $(CT_RES)/$$testdriver.txt ;\
	done

r_enc: $(U_ENC)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running encoders test driver: $$testdriver ... ; \
		$(CTB_UENC)/$$testdriver.exe > $(CT_RES)/$$testdriver.txt ;\
	done

r_dig: $(U_DIG)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running digests test driver: $$testdriver ... ; \
		$(CTB_UDIG)/$$testdriver.exe > $(CT_RES)/$$testdriver.txt ;\
	done

r_rnd: $(U_RND)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running random generators test driver: $$testdriver ... ; \
		$(CTB_URND)/$$testdriver.exe > $(CT_RES)/$$testdriver.txt ;\
	done

r_bc: $(U_BC)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running block ciphers test driver: $$testdriver ... ; \
		$(CTB_UBC)/$$testdriver.exe > $(CT_RES)/$$testdriver.txt ;\
	done
    
r_time: r_t_dig

r_t_dig: $(T_DIG)
	for testdriver in $(basename $(notdir $^)); do \
		echo Running digest time trial: $$testdriver ... ; \
		$(CTB_TDIG)/$$testdriver.exe > $(CT_RES)/$$testdriver.txt ;\
	done
