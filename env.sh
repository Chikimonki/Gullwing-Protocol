#!/bin/bash
export MOABI_ROOT="/mnt/d/moabi"
export PATH="${MOABI_ROOT}/bin:/opt/zig:${PATH}"
export LD_LIBRARY_PATH="${MOABI_ROOT}/lib:${LD_LIBRARY_PATH:-}"
export C_INCLUDE_PATH="${MOABI_ROOT}/include:${C_INCLUDE_PATH:-}"
export PKG_CONFIG_PATH="${MOABI_ROOT}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
echo "[moabi env loaded] root=${MOABI_ROOT}"
