# CleanReflectiveDLLInjection
reflective dll injection + cleanup for raw file\
anatomy is quite simple - the idea is to allocate additionaly to the image size - size for a small stub program\
that will zero the memory of the raw file, free the allocation for the raw file and finally call the original entry point\
This project relies heavily on:\
https://github.com/stephenfewer/ReflectiveDLLInjection (obviously)\
https://github.com/czs108/PE-Packer/blob/master/src/shell/entry_x86.asm

