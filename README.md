# Ghidra Scripts
Collection of various small Ghidra scripts to assist in reverse engineering.

## Installation
Copy script(s) to your Ghidra/Features/Python/ghidra_scripts/ directory. Launch from the Script Manager. 

## Scripts
### DisassembleAddresses.py
Simple script to disassemble all addresses from a text file. Each address should be in hex and on it's own line. I found it useful when I had a CPU trace and was reverse engineering a memory dump that Ghidra did not disassemble well. 

### RecursiveDecompile.py
Given a list of one or more functions, recursively decompile the function, its called functions, and enums and structs. The input file should contain a list of newline separated functions. I found this script useful when wanting to reimplement a portion of the reversed program in C without having to decompile the entire program. 
