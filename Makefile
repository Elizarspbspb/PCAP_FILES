# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/home/elizar/Рабочий стол/kiberoop/pcap_files"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/home/elizar/Рабочий стол/kiberoop/pcap_files"

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/bin/cmake-gui -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start "/home/elizar/Рабочий стол/kiberoop/pcap_files/CMakeFiles" "/home/elizar/Рабочий стол/kiberoop/pcap_files/CMakeFiles/progress.marks"
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start "/home/elizar/Рабочий стол/kiberoop/pcap_files/CMakeFiles" 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named pcap

# Build rule for target.
pcap: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 pcap
.PHONY : pcap

# fast build rule for target.
pcap/fast:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/build
.PHONY : pcap/fast

callback.o: callback.cpp.o

.PHONY : callback.o

# target to build an object file
callback.cpp.o:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/callback.cpp.o
.PHONY : callback.cpp.o

callback.i: callback.cpp.i

.PHONY : callback.i

# target to preprocess a source file
callback.cpp.i:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/callback.cpp.i
.PHONY : callback.cpp.i

callback.s: callback.cpp.s

.PHONY : callback.s

# target to generate assembly for a file
callback.cpp.s:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/callback.cpp.s
.PHONY : callback.cpp.s

formjson.o: formjson.cpp.o

.PHONY : formjson.o

# target to build an object file
formjson.cpp.o:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/formjson.cpp.o
.PHONY : formjson.cpp.o

formjson.i: formjson.cpp.i

.PHONY : formjson.i

# target to preprocess a source file
formjson.cpp.i:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/formjson.cpp.i
.PHONY : formjson.cpp.i

formjson.s: formjson.cpp.s

.PHONY : formjson.s

# target to generate assembly for a file
formjson.cpp.s:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/formjson.cpp.s
.PHONY : formjson.cpp.s

main.o: main.cpp.o

.PHONY : main.o

# target to build an object file
main.cpp.o:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/main.cpp.o
.PHONY : main.cpp.o

main.i: main.cpp.i

.PHONY : main.i

# target to preprocess a source file
main.cpp.i:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/main.cpp.i
.PHONY : main.cpp.i

main.s: main.cpp.s

.PHONY : main.s

# target to generate assembly for a file
main.cpp.s:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/main.cpp.s
.PHONY : main.cpp.s

protocols.o: protocols.cpp.o

.PHONY : protocols.o

# target to build an object file
protocols.cpp.o:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/protocols.cpp.o
.PHONY : protocols.cpp.o

protocols.i: protocols.cpp.i

.PHONY : protocols.i

# target to preprocess a source file
protocols.cpp.i:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/protocols.cpp.i
.PHONY : protocols.cpp.i

protocols.s: protocols.cpp.s

.PHONY : protocols.s

# target to generate assembly for a file
protocols.cpp.s:
	$(MAKE) -f CMakeFiles/pcap.dir/build.make CMakeFiles/pcap.dir/protocols.cpp.s
.PHONY : protocols.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... pcap"
	@echo "... callback.o"
	@echo "... callback.i"
	@echo "... callback.s"
	@echo "... formjson.o"
	@echo "... formjson.i"
	@echo "... formjson.s"
	@echo "... main.o"
	@echo "... main.i"
	@echo "... main.s"
	@echo "... protocols.o"
	@echo "... protocols.i"
	@echo "... protocols.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

