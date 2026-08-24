package=liboqs

# liboqs is driven by cmake, which learns nothing about the target from the
# environment the way an autotools package does. Without these it configures
# for the build machine: CMAKE_C_COMPILER resolves to whatever `cc` is on PATH
# and CMAKE_SYSTEM_PROCESSOR to the build machine's, so every host gets a
# build-machine liboqs.a. Upstream expects a toolchain file for this
# (.CMake/toolchain_*.cmake); the same three variables passed directly keep it
# in one place and derived from what depends already knows.
#
# The names are upstream's own, from those toolchain files.
liboqs_system_name_linux=Linux
liboqs_system_name_darwin=Darwin
liboqs_system_name_mingw32=Windows

liboqs_system_processor_x86_64=x86_64
liboqs_system_processor_i686=i586
liboqs_system_processor_arm=arm32v7
liboqs_system_processor_aarch64=arm64v8

# Setting CMAKE_SYSTEM_NAME to Windows makes cmake enable the RC language, and
# it derives the resource compiler from the C compiler's name. The wrapper below
# hides the host prefix, so name windres explicitly.
liboqs_toolchain_extra_mingw32=set(CMAKE_RC_COMPILER $(host)-windres)

# cmake is told about the target through a toolchain file, which is how
# upstream expects it (.CMake/toolchain_*.cmake). A depends CC is often several
# words: `gcc -m64`, or darwin's, which begins with `env -u ...` to clear the
# native include paths. CMAKE_C_COMPILER takes one executable, so a wrapper
# execs the whole command. The assembler needs it too, since liboqs builds .S
# sources as the ASM language and cmake stops guessing once cross-compiling.
#
# The file locates the wrapper through CMAKE_CURRENT_LIST_DIR rather than a
# shell substitution: these recipes are expanded twice, so a bare $$(pwd) is
# consumed by make instead of reaching the shell.
define liboqs_write_toolchain
	printf '#!/bin/sh\nexec %s "$$$$@"\n' '$(liboqs_cc)' > cc-wrapper && \
	chmod +x cc-wrapper && \
	printf '%s\n' \
	  'set(CMAKE_SYSTEM_NAME $(liboqs_system_name_$(host_os)))' \
	  'set(CMAKE_SYSTEM_PROCESSOR $(liboqs_system_processor_$(host_arch)))' \
	  'set(CMAKE_C_COMPILER "$$$${CMAKE_CURRENT_LIST_DIR}/cc-wrapper")' \
	  'set(CMAKE_ASM_COMPILER "$$$${CMAKE_CURRENT_LIST_DIR}/cc-wrapper")' \
	  'set(CMAKE_C_FLAGS "$(liboqs_cflags) $(liboqs_cppflags)")' \
	  '$(liboqs_toolchain_extra_$(host_os))' \
	  > toolchain.cmake
endef

liboqs_cmake_flags=-DCMAKE_TOOLCHAIN_FILE=toolchain.cmake \
	-DCMAKE_INSTALL_PREFIX=$(host_prefix) \
	-DCMAKE_INSTALL_LIBDIR=lib

ifneq ($(LIBOQS_RACCOON),)
# Raccoon fork (edtubbs/liboqs) — Falcon-512, Dilithium2, and Raccoon-G-44
$(package)_version=v0.0.3
$(package)_download_path=https://github.com/edtubbs/liboqs/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=fcacef5451fd63610b53f4483f7ef79eaa28173ffb1fcce353400ec992d4c846

define $(package)_build_cmds
	mkdir -p build && cd build && \
	$(liboqs_write_toolchain) && \
	cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=OFF \
		-DOQS_ENABLE_SIG_RACCOON_G=ON -DOQS_ENABLE_SIG_raccoon_g_44=ON \
		-DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_falcon_512;SIG_falcon_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_slh_dsa_pure_shake_128s;SIG_slh_dsa_pure_shake_128f;SIG_raccoon_g_44" \
		$(liboqs_cmake_flags) .. && \
	$(MAKE)
endef

else
# Upstream liboqs (open-quantum-safe) — Falcon-512 and Dilithium2 only
$(package)_version=0.15.0
$(package)_download_path=https://github.com/open-quantum-safe/liboqs/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c

define $(package)_build_cmds
	mkdir -p build && cd build && \
	$(liboqs_write_toolchain) && \
	cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=OFF \
		-DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_falcon_512;SIG_falcon_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_slh_dsa_pure_shake_128s;SIG_slh_dsa_pure_shake_128f" \
		$(liboqs_cmake_flags) .. && \
	$(MAKE)
endef

endif

define $(package)_stage_cmds
	cd build && $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
