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

Below kernel configurations are required:

```
CONFIG_INTEL_TDX_GUEST=y
CONFIG_TCG_TPM=y
CONFIG_TCG_CRB=y
CONFIG_IMA=y
```

A reference kernel config is available at [Patches/Kernel](Patches/Kernel/reference-config-guest)

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

### tpm2-tools
It’s recommended to build and install tpm2-tools in TD guest image.
Please install the following dependencies before building and installing tpm2-tools.
```
$ sudo apt-get -y install \
      autoconf-archive libcmocka0 libcmocka-dev procps iproute2 \
      build-essential git pkg-config gcc libtool automake libssl-dev \
      uthash-dev autoconf doxygen libjson-c-dev libini-config-dev \
      libcurl4-openssl-dev uuid-dev libltdl-dev libusb-1.0-0-dev \
      libarchive-dev clang libglib2.0-dev
```
Follow document: [tpm2-tools document](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/) to build and install tpm2-tools.

#### Run tpm2 commands in TD
For example, run tpm2_pcrread to read the PCR registers.
```
tpm2_pcrread
```
The output is like:
```
  sha256:
    0 : 0x6EEB7D7776BD6917F9595F6AC643EA7102861ED2E6204BB16E5ED5FE8DF19435
    1 : 0xAD2E8C8588627F7DEF8340ED8B3D459D25FD42D67BC54E8A3161345C7EC9FCC2
    2 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    3 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    4 : 0x6FE4C4AA1593841114E77CE3ED2EDA2CB07796EA42E46281068406D41EF1EEA8
    5 : 0xA5CEB755D043F32431D63E39F5161464620A3437280494B5850DC1B47CC074E0
    6 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    7 : 0xB5710BF57D25623E4019027DA116821FA99F5C81E9E38B87671CC574F9281439
    8 : 0x0000000000000000000000000000000000000000000000000000000000000000
    9 : 0xE0C40B1D01B7EB88BD00FE4D465E38B86846C59E9C441274125DAFF7ACC2CA1A
    10: 0x93E94F77D78CF172D93E99E1F44769F7FB20990C3F02052F917A0CBA163A363D
    11: 0x0000000000000000000000000000000000000000000000000000000000000000
    12: 0x0000000000000000000000000000000000000000000000000000000000000000
    13: 0x0000000000000000000000000000000000000000000000000000000000000000
    14: 0x0000000000000000000000000000000000000000000000000000000000000000
    15: 0x0000000000000000000000000000000000000000000000000000000000000000
    16: 0x0000000000000000000000000000000000000000000000000000000000000000
    17: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    18: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    19: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    20: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    21: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    22: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
...
```
### keylime & Linux IMA
vTPM can be used for Keylime to do remote attestation with Linux IMA enabled. Keylime verifier will do continually remote attestation with Linux IMA measurement records protected with vTPM from Keylime agent deployed inside TDVM and compare against know good values provided by trusted admin or third parties.
#### Keylime Installation
Boot a TD with vTPM enabled as above. Install Keylime verifier, Keylime registrar and Keylime agent in TD:
```
sudo useradd keylime -g tss
git clone https://github.com/keylime/keylime.git
cd keylime
./installer.sh 
```
Keylime agent is rust based, please follow https://www.rust-lang.org/tools/install to install rust runtime. Keylime agent depends on tpm2-tss and tpm2-tools to be installed as perquisitions, please follow [tpm2-tools document](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/) to install them.
```
git clone https://github.com/keylime/rust-keylime.git 
cd rust-keylime
cargo build --release
cp target/release/keylime_agent /usr/local/bin/
```
#### Configuration
Add 'ima_policy=critical_data' in kernel boot command line, he Linux IMA measurement records can be found at /sys/kernel/security/ima/ascii_runtime_measurements:
```
10 beab1f23c09f6458e298b123c8f8a647559ce772 ima-ng sha256:6754a6b5ef16e241674dd59c8ff99964b075d9d8b87a767bc3e144b2fc508676 boot_aggregate
10 897bd9521b5e83ccc0aea36b3530e1deb5cb6f91 ima-buf sha256:fefe31aa320223a0ba73eb5e28a05ee7fd9a459a1f7e26c4240b0998d51b7d43 kernel_version 362e322e31362d6d7670333076332b372d67656e65726963
```
Generate a Keylime runtime policy file using the IMA measurement records:
```
keylime_create_policy -b -m /sys/kernel/security/ima/ascii_runtime_measurements -o runtime_policy.json
```
The generated policy file runtime_policy.json as below:
```
{"meta": {"version": 1, "generator": 1}, "release": 0, "digests": {"boot_aggregate": ["6754a6b5ef16e241674dd59c8ff99964b075d9d8b87a767bc3e144b2fc508676"]}, "excludes": [], "keyrings": {}, "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1", "dm_policy": null}, "ima-buf": {"kernel_version": ["fefe31aa320223a0ba73eb5e28a05ee7fd9a459a1f7e26c4240b0998d51b7d43"]}, "verification-keys": ""}
```
Prepare a payload file payload.txt for tenant command be used when registering agent to verifier:
```
echo "12345678" >  payload.txt
```
Change configure files in /etc/keylime to make sure it uses same hash algorithm as Linux IMA does:
```
tpm_hash_alg = "sha256" #agent.conf
transparency_log_sign_algo = sha256 #registrar.conf
transparency_log_sign_algo = sha256 #verifier.conf
Change configure /etc/keylime/tenant.conf for to ask tenant to use self-signed EK certificate.
require_ek_cert = False
```
Make sure /var/lib/keylime and all sub directories have owner run_as “keylime:tss” if specified in /etc/keylime/agent.conf, if not, please use following command to set the owner and group.
```
sudo chown -R keylime:tss /var/lib/keylime
```
#### Start Keylime Components
Start Keylime verifier, Keylime registrar and Keylime agent.
```
keylime_verifier > keylime_verifier.log 2>&1 &
keylime_registrar > keylime_registrar.log 2>&1 &
keylime_agent > keylime_agent.log 2>&1 &
```
Add Keylime agent to verifier to do continues remote attestation:
```
keylime_tenant -c add --uuid d432fbb3-d2f1-4a97-9ef7-75bd81c00000 -f ./payload.txt --runtime-policy ./runtime_policy.json
```
Use following commands to check Keylime system status:
```
keylime_tenant -c reglist
keylime_tenant -c cvstatus
keylime_tenant -c regstatus
```
Use following command to remove the agent from verifier:
```
keylime_tenant -c delete -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000
```
## What has been tested:
 - TPM event log/PCR replay in L2 Linux
 - Endorsement Key certificate and CA certificate read and verify.
 - Quote verification with [Linux Stack for TDX](https://www.intel.com/content/www/us/en/content-details/783067/whitepaper-linux-stacks-for-intel-trust-domain-extension-1-0.html)

