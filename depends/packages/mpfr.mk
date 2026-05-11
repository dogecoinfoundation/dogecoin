package=mpfr
# MPFR is the C analogue of Python's mpmath used by the upstream Raccoon-G
# reference (p-11/lattice-hd-wallets) for the rounded Gaussian sampler. It
# provides IEEE-754 correctly-rounded arbitrary-precision floating-point and
# is required for the byte-exact KAT gate of the in-tree Raccoon-G-44 port
# (src/raccoon_g/gaussian.c). Only fetched/built when RACCOON_G=y.
$(package)_version=4.2.1
$(package)_download_path=https://ftp.gnu.org/gnu/mpfr
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=277807353a6726978996945af13e52829e3abd7a9a5b7fb2793894e18f1fcbb2
$(package)_dependencies=gmp

define $(package)_set_vars
$(package)_config_opts=--disable-shared --enable-static --with-pic
$(package)_config_opts+=--with-gmp=$(host_prefix)
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
