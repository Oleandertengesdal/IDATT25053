# Hello World in C

## Prerequisites
  * Linux

## Installing dependencies

### Debian based distributions
`sudo apt-get install binutils`

### Arch Linux based distributions
`sudo pacman -S binutils`

## Compiling and running
```sh
git clone https://gitlab.com/ntnu-tdat3020/c-example
cd c-example
```

### Alternative 1 in [juCi++](https://gitlab.com/cppit/jucipp):
Run `juci .` and choose Compile and Run in the Project menu.

### Alternative 2:
```sh
gcc main.c a_function.c more_functions.c -o c_example
./c_example
```

## Assembly output from the C-sources

### Create assembly output
```sh
gcc -S -masm=intel main.c a_function.c more_functions.c  # Create assembly sources from the C-sources
cat main.s                                               # Print the assembly sources to the terminal
cat a_function.s
cat more_functions.s
```

### Compiling and running assembly sources
```sh
as main.s -o main.o                                    # Compile sources to object files that contains machine code
as a_function.s -o a_function.o                        # and references to functions or variables found
as more_functions.s -o more_functions.o                # in other object files or libraries.

gcc main.o a_function.o more_functions.o -o c_example  # Link object files and create executable. The machine code
                                                       # of all the object files are here combined into one
                                                       # executable, but references to dynamic libraries are kept.
./c_example
```

## Create and use a static library (archive file) from a_function.c and more_functions.c

### Create the static library libfunctions.a
```sh
gcc -c a_function.c more_functions.c                # Create object files
ar -r libfunctions.a a_function.o more_functions.o  # Create libfunctions.a from the object files
```

### List the contents of libfunctions.a
```sh
ar -t libfunctions.a
```

### Create executable from main.c and libfunctions.a
```sh
gcc main.c libfunctions.a -o c_example
./c_example
```

## Create and use a dynamic library (shared object file) from a_function.c and more_functions.c

### Create the dynamic library libfunctions.so
```sh
gcc -c -fPIC a_function.c more_functions.c                    # Create object files for the shared library
gcc -shared a_function.o more_functions.o -o libfunctions.so  # Create libfunctions.so from the object files
sudo cp libfunctions.so /usr/lib                              # Copy the library to the system library path
                                                              # You can delete /usr/lib/libfunctions.so after the exercise
```

### Compile main.c and dynamically link to libfunctions.so
```sh
gcc main.c -lfunctions -o c_example
./c_example
```

#### See the dynamic library dependencies of c_example
```sh
ldd c_example
```
