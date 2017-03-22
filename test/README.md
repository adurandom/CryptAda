# CryptAda test drivers #
This directory contains the test drivers for the different CryptAda packages.

CryptAda test drivers come in two flavours:
* Unit test drivers that exercise the functionality of some CryptAda elements, and
* Time trials that attempt to clock execution of CryptAda algorithms.

Under test directory are the following subdirectories:
* `res` directory contains the files containing the output of test execution (both unit and time trial tests)
* `src`directory contains the test source code.

## CryptAda test sources

CryptAda test drivers are built according the following schema:
* For each test driver there are three files:
  * An Ada procedure body
  * An Ada package specification
  * An Ada package body.
  
The procedure simply calls a procedure in the package that execte the different test cases. 

Code is organized in different directories under `src` directory. 

Subdir name|Description
-----------|-----------
base|Base packages for testing
utils|Utility functionality for testing
uut_drv|Unit test drivers for utility packages
uut_pkg|Unit test packages for utility packages
upr_drv|Unit test drivers for *CryptAda.Pragmatics* functionality
upr_pck|Unit test driver packages for *CryptAda.Pragmatics* functionality
uen_drv|Unit test drivers for *CryptAda.Encoders* functionality
uen_pck|Unit test driver packages for *CryptAda.Encoders* functionality
udi_drv|Unit test drivers for *CryptAda.Digests* functionality
udi_pck|Unit test driver packages for *CryptAda.Digests* functionality
urn_drv|Unit test drivers for *CryptAda.Random.Generators* functionality
urn_pck|Unit test driver packages for *CryptAda.Random.Generators* functionality
ubn_drv|Unit test drivers for *CryptAda.Big_Naturals* functionality
ubn_pck|Unit test driver packages for *CryptAda.Big_Naturals* functionality



