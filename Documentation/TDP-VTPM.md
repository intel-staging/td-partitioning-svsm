## TDP environment setup

For host Kernel, QEMU and guest image setup, please follow [INSTALLATION_GUIDE](https://github.com/intel-staging/td-partitioning-svsm/blob/svsm-tdp-patches/INSTALLATION_GUIDE.md).

vTPM requires additional patches for OVMF and TDP guest Linux Kernel. Please follow [Setup OVMF](#Setup-OVMF) and [Setup TDP guest Linux Kernel](#Setup-TDP-guest-Linux-Kernel) to build the images.

## Setup OVMF

### Prepare OVMF tree

Download the source code:

```
git clone --branch edk2-stable202402 --single-branch https://github.com/tianocore/edk2.git
cd edk2 && git checkout -b ovmf-svsm-tdp
```

The TDP OVMF patches in [Patches/OVMF](Patches/OVMF), apply the patches:
```
git am --ignore-whitespace <path-to-patches>/*\.patch
```

### Build OVMF

Please note that `-DTPM2_ENABLE` needs to be enabled for vTPM.

```
git submodule update --init --recursive
make -C BaseTools clean && make -C BaseTools
source ./edksetup.sh
build -a X64 -b DEBUG -t GCC5 -D FD_SIZE_2MB -DTPM2_ENABLE -D DEBUG_ON_SERIAL_PORT -D DEBUG_VERBOSE -p OvmfPkg/OvmfPkgX64.dsc
```

OVMF image can be found at Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd

## Setup TDP guest Linux Kernel

### Prepare Linux Kernel source code

```
git clone --branch v6.6 --single-branch https://github.com/torvalds/linux.git
cd linux/
git switch -c v6.6
```

The TDP guest Kernel patches in [Patches/Kernel](Patches/Kernel), apply the patches:

```
git am --ignore-whitespace <path-to-patches>/*\.patch
```

### Build TDP guest Kernel

Enable TDX_GUEST config:

```
scripts/config --enable CONFIG_INTEL_TDX_GUEST
```

Build Kernel image:

```
make
```

## Features included
 - vTPM CRB MMIO interface
 - vTPM CA generation with TDX remote attestation
 - vTPM Endorsement Key certificate and CA provision
 - TDP L2 guest vTPM detection through TDVMCALL
 - SVSM vTPM startup and measurement (SVSM version and TDVF).
 - Ephemeral vTPM NVS

## Test Utility
 - [tpm2-tools](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/)
 - [Keylime](https://github.com/keylime/rust-keylime)
 - [Linux IMA](https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture)

## What has been tested:
 - TPM event log/PCR replay in L2 Linux
 - Endorsement Key certificate and CA certificate read and verify.
 - Quote verification with [Linux Stack for TDX](https://www.intel.com/content/www/us/en/content-details/783067/whitepaper-linux-stacks-for-intel-trust-domain-extension-1-0.html)

