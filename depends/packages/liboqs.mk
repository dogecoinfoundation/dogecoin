package=liboqs
# Mainline liboqs (open-quantum-safe), Falcon-512 and Dilithium2.
$(package)_version=0.15.0
$(package)_download_path=https://github.com/open-quantum-safe/liboqs/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c

define $(package)_build_cmds
	mkdir -p build && cd build && \
	cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=OFF \
		-DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_falcon_512;SIG_falcon_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_slh_dsa_pure_shake_128s;SIG_slh_dsa_pure_shake_128f" \
		-DCMAKE_INSTALL_PREFIX=$(host_prefix) .. && \
	$(MAKE)
endef

define $(package)_stage_cmds
	cd build && $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
