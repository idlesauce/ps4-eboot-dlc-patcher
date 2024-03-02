@echo off
SETLOCAL EnableDelayedExpansion

REM Store the current directory
set "original_dir=%CD%"

REM Change the working directory to the script's location
cd %~dp0

REM Libraries to link in
set libraries=-lc -lkernel -lSceSysmodule -lSceAppContent -lSceAppContentIro -lSceAppContentSc -lc++

set intdir=.\temp
set targetname=dlcldr
set outputPath=%cd%\bin

set outputElf=%intdir%\%targetname%.elf
set outputOelf=%intdir%\%targetname%.oelf
set outputPrx=%targetname%.prx
set outputStub=%targetname%_stub.so

if not exist "%intdir%" mkdir "%intdir%"
if not exist "%outputPath%" mkdir "%outputPath%"

REM Compile object files for all the source files
for %%f in (*.c) do (
    clang --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -I"%OO_PS4_TOOLCHAIN%\\include" %extra_flags% -c -o %intdir%\%%~nf.o %%~nf.c || (
        echo Error: Compilation failed for %%~nf.c
        goto :cleanup
    )
)

for %%f in (*.cpp) do (
    clang++ --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -I"%OO_PS4_TOOLCHAIN%\\include" -I"%OO_PS4_TOOLCHAIN%\\include\\c++\\v1" %extra_flags% -c -o %intdir%\%%~nf.o %%~nf.cpp || (
        echo Error: Compilation failed for %%~nf.cpp
        goto :cleanup
    )
)

for %%f in (*.s) do (
    clang --target=x86_64-pc-freebsd12-elf -mllvm -x86-asm-syntax=intel -fPIC -funwind-tables -I"%OO_PS4_TOOLCHAIN%\\include" %extra_flags% -c -o %intdir%\%%~nf.o %%~nf.s || (
        echo Error: Compilation failed for %%~nf.s
        goto :cleanup
    )
)

REM Get a list of object files for linking
set "obj_files="
for %%f in (%intdir%\*.o) do set "obj_files=!obj_files! .\%%f"

REM Link the input ELF
ld.lld -m elf_x86_64 -pie --script "%OO_PS4_TOOLCHAIN%\link.x" --eh-frame-hdr -o "%outputElf%" "-L%OO_PS4_TOOLCHAIN%\lib" %libraries% --verbose -e "module_start" %obj_files% || (
    echo Error: Linking failed.
    goto :cleanup
)

REM Create stub shared libraries
for %%f in (*.c) do (
    clang -target x86_64-pc-linux-gnu -ffreestanding -nostdlib -fno-builtin -fPIC -c -I"%OO_PS4_TOOLCHAIN%\include" -o %intdir%\%%~nf.o.stub %%~nf.c || (
        echo Error: Stub Compilation failed for %%~nf.c
        goto :cleanup
    )
)

for %%f in (*.cpp) do (
    clang++ -target x86_64-pc-linux-gnu -ffreestanding -nostdlib -fno-builtin -fPIC -c -I"%OO_PS4_TOOLCHAIN%\include" -I"%OO_PS4_TOOLCHAIN%\\include\\c++\\v1" -o %intdir%\%%~nf.o.stub %%~nf.cpp || (
        echo Error: Stub Compilation failed for %%~nf.cpp
        goto :cleanup
    )
)

set "stub_obj_files="
for %%f in (%intdir%\*.o.stub) do set "stub_obj_files=!stub_obj_files! .\%%f"

clang++ -target x86_64-pc-linux-gnu -shared -fuse-ld=lld -ffreestanding -nostdlib -fno-builtin "-L%OO_PS4_TOOLCHAIN%\lib" %libraries% %stub_obj_files% -o "%outputStub%" || (
    echo Error: Creating stub shared library failed.
    goto :cleanup
)

REM Create the prx
%OO_PS4_TOOLCHAIN%\bin\windows\create-fself.exe -in "%outputElf%" --out "%outputOelf%" --lib "%outputPrx%"  --libname "%targetname%" --paid 0x3800000000000011 || (
    echo Error: Creating PRX failed.
    goto :cleanup
)

REM Cleanup
:cleanup
if exist "%outputPath%\%outputPrx%" del "%outputPath%\%outputPrx%"
if exist "%outputPath%\%targetname%_unsigned.elf" del "%outputPath%\%targetname%_unsigned.elf"

REM Move files
move %outputPrx% %outputPath%\%outputPrx%
move %outputOelf% %outputPath%\%targetname%_unsigned.elf

del %outputStub%
rd /s /q %intdir%

REM Restore the original directory
cd %original_dir%

REM End the local scope
endlocal
