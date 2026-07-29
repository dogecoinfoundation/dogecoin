package=gmp
# GMP is required by MPFR, which is in turn required by the in-tree
# Raccoon-G-44 Gaussian sampler under src/raccoon_g/gaussian.c. It is only
# fetched/built when RACCOON_G=y is passed to the depends top-level Makefile.
$(package)_version=6.3.0
$(package)_download_path=https://ftp.gnu.org/gnu/gmp
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898

define $(package)_set_vars
$(package)_config_opts=--disable-shared --enable-static --enable-cxx=no
$(package)_config_opts+=--with-pic
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
