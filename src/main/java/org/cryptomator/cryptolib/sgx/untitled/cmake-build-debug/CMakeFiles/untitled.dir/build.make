# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/storage/Documentos/clion-2018.3.4/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/storage/Documentos/clion-2018.3.4/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/untitled.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/untitled.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/untitled.dir/flags.make

CMakeFiles/untitled.dir/library.cpp.o: CMakeFiles/untitled.dir/flags.make
CMakeFiles/untitled.dir/library.cpp.o: ../library.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/untitled.dir/library.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/untitled.dir/library.cpp.o -c /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/library.cpp

CMakeFiles/untitled.dir/library.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/untitled.dir/library.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/library.cpp > CMakeFiles/untitled.dir/library.cpp.i

CMakeFiles/untitled.dir/library.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/untitled.dir/library.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/library.cpp -o CMakeFiles/untitled.dir/library.cpp.s

# Object files for target untitled
untitled_OBJECTS = \
"CMakeFiles/untitled.dir/library.cpp.o"

# External object files for target untitled
untitled_EXTERNAL_OBJECTS =

libuntitled.so: CMakeFiles/untitled.dir/library.cpp.o
libuntitled.so: CMakeFiles/untitled.dir/build.make
libuntitled.so: CMakeFiles/untitled.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libuntitled.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/untitled.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/untitled.dir/build: libuntitled.so

.PHONY : CMakeFiles/untitled.dir/build

CMakeFiles/untitled.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/untitled.dir/cmake_clean.cmake
.PHONY : CMakeFiles/untitled.dir/clean

CMakeFiles/untitled.dir/depend:
	cd /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/cmake-build-debug /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/cmake-build-debug /home/storage/Documentos/cryptolib/src/main/java/org/cryptomator/cryptolib/sgx/untitled/cmake-build-debug/CMakeFiles/untitled.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/untitled.dir/depend

