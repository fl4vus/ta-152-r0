# ta-152-r0
![MASCOT](https://raw.githubusercontent.com/fl4vus/ta-152-r0/main/r0_mascot.png)

## TA-152-R0 Cipher (Original Implementation)
TA-152-R0 is a polyalphabetic, per-round evolving cipher algorithm designed by me.
The implementation is deterministic, and bare-bones, with **EXPERIMENTAL** stability, and is not suitable for production cryptography.

### Build Instructions
```
git clone https://github.com/fl4vus/ta-152-r0
cd ta-152-r0/
make
```

### Usage
```
./ta152 encrypt <input_file> <keyfile>     # Encryption
./ta152 decrypt <input_file> <keyfile>     # Decryption
```

### Build
Language: ISO C11  
Compiler: GCC / Clang  
Platform: Linux / Unix  
Build system: Make  
Dependencies: libc only  

### Documentation
Specifications: [TA-152-R0-SPEC](https://github.com/fl4vus/ta-152-r0/tree/main/documentation/r0_spec.pdf)

_AUTHOR: Riyan Dahiya_
