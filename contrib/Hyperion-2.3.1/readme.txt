###############################################################################
#                                                                             #
#         ~    .__ °.__   0       o                    ^   .__ °__  `´        #
#  °____) __ __|  | | °|   ______°____ 0 ____  __ _________|__|/  |_ ___.__.  #
#  /    \|  | °\  |°|  | °/  ___// __ \_/ ___\|  | °\_  __ \ o\   __<   |  |  #
# | o°|  \  |  /  |_|  |__\___ \\  ___/\ °\___| o|  /|  | \/  ||  |° \___ O|  #
# |___|  /____/|____/____/____ °>\___  >\___  >____/ |__|° |__||__|  / ____|  #
# `´´`´\/´`nullsecurity team`´\/`´´`´\/`´``´\/  ``´```´```´´´´`´``0_o\/´´`´´  #
#                                                                             #
# Hyperion: A runtime PE-Crypter                                              #
#                                                                             #
# VERSION                                                                     #
# 2.3.1                                                                       #
#                                                                             #
# DATE                                                                        #
# 03/23/2020                                                                  #
#                                                                             #
# AUTHOR                                                                      #
# belial - http://www.phobosys.de/hyperion                                    #
#                                                                             #
# LICENSE                                                                     #
# BSD-License                                                                 #
#                                                                             #
# DESCRIPTION                                                                 #
# Hyperion is a runtime encrypter for 32/64 bit portable executables. It is a #
# reference implementation and bases on the paper "Hyperion: Implementation   #
# of a PE-Crypter". The paper describes the implementation details which      #
# aren't in the scope of this readme file.                                    #
# The crypter is a C project and can be compiled with the corresponding       #
# makefile (tested with Mingw and Visual Studio). Afterwards it is started    #
# via the command line and encrypts an input executable with AES-128. The     #
# encrypted file decrypts itself on startup (bruteforcing the AES key which   #
# may take a few seconds) and generates a log file for debug purpose.         #
#                                                                             #
# TODO                                                                        #
# - AES payload: Maybe use Windows crypto API instead because our fasm aes    #
#   payload is full of static tables                                          #
# - Better crypto blob hiding/obfuscation                                     #
# - Dynamically morph code and add junk code                                  #
# - Support late Binding of DLLs/APIs                                         #
# - Check for correct DLL Version Numbers before Loading                      #
# - Analysis: What else is missing in PE loader                               #
# - Provide hyperion as free a web service to hide advanced implementation    #
#   details                                                                   #
#                                                                             #
# CHANGELOG:                                                                  #
#                                                                             #
# v2.3.1:                                                                     #
# - bugfix in .net file detection                                             #
#                                                                             #
# v2.3:                                                                       #
# - log message strings were still in non-log binaries -> removed             #
# - each function uses shadow registers -> preparation for code morphing      #
# - basic win32 apis are part of import table and not loaded dynamically      #
# - output size for non-log binaries reduced by 4kb                           #
# - 32 bit is now deprecated                                                  #
# - preserve GUI/Console Flag                                                 #
# - abort if input is a .NET executable                                       #
#                                                                             #
# v2.2:                                                                       #
# - removed aes.dll blob and use tinyAes c implementation instead             #
# - aes payload uses new FasmAES 1.3 which has several bugfixes               # 
#                                                                             #
# v2.1:                                                                       #
# - crappy makefile cleanup                                                   #
#                                                                             #
# v2.0:                                                                       #
# - added 64-bit support                                                      #
# - upgraded fasm.exe to 1.71                                                 #
# - flexible payload structure to add your own ecryption algos                #
# - removed c++ code and added pure c instead                                 #
#                                                                             #
# v1.2:                                                                       #
# - added windows 8 and 8.1 support (thx to CoolOppo)                         #
#                                                                             #
# v1.1:                                                                       #
# - code cleanup and refactoring (more leightweighted and increased           #
#   maintainability)                                                          #
# - change key space size via the command line                                #
# - change key length via the command line                                    #
# - disable logfile generation of the container via commandline               #
# - display verbose informations while running                                #
#                                                                             #
# v1.0:                                                                       #
# - initial release                                                           #
#                                                                             #
###############################################################################
