# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

#rte_eth_read_clock is experimental
project('ping_dpdk', 'c',
      version : '1,0,0',
      LISENSE : 'MIT')

allow_experimental_apis = true

dpdklib = dependency('libdpdk')

rxtx_callback = executable('ping_dpdk',
	'main.c',
	dependencies : dpdklib)
