# Introduction

## 1. Prerequisite Setup

Before proceeding, ensure that TDX is enabled, as this document does not provide instructions for enabling TDX or loading a TDX module. It is assumed that the user is already experienced with these processes.
It is also assumed that the host OS has the necessary packages installed for using the git, make, wget, and b4 commands. These tools are required for preparing the source code tree, as outlined in this guide.

The TDP related patches for host-kernel/host-qemu/OVMF are published in this repo at branch svsm-tdp-patches. Download patches:

	$ git clone https://github.com/intel-staging/td-partitioning-svsm.git <TDP-patches-folder>
	$ cd <TDP-patches-folder>
	$ git checkout -b svsm-tdp-patches remotes/origin/svsm-tdp-patches

The host-kernel patches are in <TDP-patches-folder>/linux/
The host-qemu patches are in <TDP-patches-folder>/qemu/
The OVMF patches are in <TDP-patches-folder>/ovmf/

## 2. Hardware Environment

Tested platform: Eagle Stream EMR
TDX module version: TDX_1.5.05.46.698

# Setup Host Kernel

## 1. Host Kernel Base and Patches

Host kernel is based on upstream Linux kernel v6.8.0-rc5: https://github.com/torvalds/linux/tree/v6.8-rc5

Plug applying below additional patches:
* series#1: V19 KVM TDX basic feature support: https://lore.kernel.org/all/cover.1708933498.git.isaku.yamahata@intel.com/#t
* series#2: V8 KVM TDX: TDP MMU: large page support: https://lore.kernel.org/all/cover.1708933624.git.isaku.yamahata@intel.com/#r
* series#3: Paolo’s patch about “MTRR mask values for SEV or TME”(in queue): https://lore.kernel.org/all/20240131230902.1867092-1-pbonzini@redhat.com/#r
* series#4: One workaround patch for Emulate Xen MTRR disablement from intel repo: https://github.com/intel/tdx/commit/5c1b39050a54449331e5190649c23078a2f514db
* series#5: Two workaround patches for RBP from intel repo: https://github.com/intel/tdx/commit/04c25c1d63af1c9eb1b3678d9192f44150936110 and https://github.com/intel/tdx/commit/fde917bc1af3e1a440ab0cb0d9364f8da25b9e17
* series#6: One compiling issue fix patch from comment of V19 in community: https://lore.kernel.org/all/20240226192757.GS177224@ls.amr.corp.intel.com/
  Note: this is *not* a patch in community mailing list but a replied message. This patch is created manually and included in the <TDP-patches-folder>/linux/ as 0001-Fix-kernel-compiling-issue.patch
* series#7: The TDP Linux kernel patches in the <TDP-patches-folder>/linux/ start from 0002-KVM-TDX-Enumerate-TD-partitioning-feature.patch

## 2. Prepare Host Kernel Tree

Download the v6.8-rc5 source code:

    $ git clone --branch v6.8-rc5 --single-branch https://github.com/torvalds/linux.git
    $ cd linux/
    $ git switch -c v6.8-rc5

Download and apply series#1:

    $ mkdir series
    $ b4 am -o series cover.1708933498.git.isaku.yamahata@intel.com
    $ git am series/v19_20240226_isaku_yamahata_kvm_tdx_basic_feature_support.mbx

Download and apply series#2:

    $ b4 am -o series cover.1708933624.git.isaku.yamahata@intel.com
    $ git am series/v8_20240226_isaku_yamahata_kvm_tdx_tdp_mmu_large_page_support.mbx

Download and apply series#3:

    $ b4 am -o series 20240131230902.1867092-1-pbonzini@redhat.com
    $ git am series/v2_20240201_pbonzini_x86_cpu_fix_invalid_mtrr_mask_values_for_sev_or_tme.mbx

Download and apply series#4:

    $ wget -O series/0001-KVM-TDX-Emulate-Xen-MTRR-disablement.patch https://github.com/intel/tdx/commit/5c1b39050a54449331e5190649c23078a2f514db.patch
    $ git am series/0001-KVM-TDX-Emulate-Xen-MTRR-disablement.patch

Download and apply series#5:

    $ wget -O series/0001-x86-virt-tdx-Explicitly-save-restore-RBP-for-seamcal.patch https://github.com/intel/tdx/commit/04c25c1d63af1c9eb1b3678d9192f44150936110.patch
    $ git am series/0001-x86-virt-tdx-Explicitly-save-restore-RBP-for-seamcal.patch
    $ wget -O series/0001-KVM-TDX-Don-t-use-NO_RBP_MOD-for-backward-compatibil.patch https://github.com/intel/tdx/commit/fde917bc1af3e1a440ab0cb0d9364f8da25b9e17.patch
    $ git am series/0001-KVM-TDX-Don-t-use-NO_RBP_MOD-for-backward-compatibil.patch

Series#6 and series#7 are included in the SVSM repo, so no need to download but just apply the patches:

    $ git am <TDP-patches-folder>/linux/*\.patch

## 3. Build and Install Host Kernel

### 3.1 Kernel Config

No additional kernel config is required comparing with TDX. Use the same kernel config with TDX as recommended [here](https://github.com/intel/tdx/wiki/TDX-KVM#configurations).

    CONFIG_INTEL_TDX_HOST=y
    CONFIG_KVM=y
    CONFIG_KVM_INTEL=y

When loading kvm_intel, use module parameter "kvm_intel.tdx=on". By default TDX support is disabled. For automation, add it to kernel command line, or edit modules.conf.

The <TDP-patches-folder>/linux/reference-config is a reference kernel config file with configuring KVM/KVM_INTEL as modules.

### 3.2 Build and Install Kernel

The kernel compilation process follows the standard procedure without any special requirements.

    $ make -j$(nproc)
    $ sudo make modules_install
    $ sudo make install

The kernel command line should be modified with below additional options: "kvm_intel.tdx=on nohibernate", which is the same requirement as TDX.

# Setup Host QEMU

## 1. Host QEMU Base and Patches

Host QEMU is based on upstream QEMU. Commid ID: bfe8020c814a30479a4241aaa78b63960655962b

Plus applying the following QEMU patch series:
* series#1: Confidential Guest Support: Introduce kvm_init() and kvm_reset() virtual functions: https://lore.kernel.org/qemu-devel/20240229060038.606591-1-xiaoyao.li@intel.com/
* series#2: V5 QEMU Guest memfd + QEMU TDX support: https://lore.kernel.org/qemu-devel/20240229063726.610065-1-xiaoyao.li@intel.com/
* series#3: The TDP QEMU patches in <TDP-patches-folder>/qemu/

## 2. Prepare Host QEMU Tree

Download the source code:

    $ git clone https://gitlab.com/qemu-project/qemu.git
    $ cd qemu && git checkout -b qemu-svsm-tdp bfe8020c814a30479a4241aaa78b63960655962b
    $ mkdir series
    $ git config --local b4.midmask https://lore.kernel.org/qemu-devel/%s
    $ git config --local b4.linkmask https://lore.kernel.org/qemu-devel/%s

Download and apply series#1:

    $ b4 am -o series 20240229060038.606591-1-xiaoyao.li@intel.com
    $ git am series/20240229_xiaoyao_li_confidential_guest_support_introduce_kvm_init_and_kvm_reset_virtual_functions.mbx

Download and apply series#2:

    $ b4 am -o series 20240229063726.610065-1-xiaoyao.li@intel.com
    $ git am series/v5_20240229_xiaoyao_li_qemu_guest_memfd_qemu_tdx_support.mbx

Series#3 is included in the SVSM repo, so no need to download but just apply the patches:

    $git am <TDP-patches-folder>/qemu/*\.patch

## 3. Build and Install Host QEMU

The QEMU compilation process follows the standard procedure without any special requirements.

    $ ./configure --prefix=$HOME/bin/qemu-svsm/ --target-list=x86_64-softmmu
    $ ninja -C build/
    $ make install

# Setup OVMF

## 1. OVMF Base and Patches

Guest OVMF is based on upstream EDK II. Tag: edk2-stable202402
Plus applying the following OVMF patch series:
* series#1: The TDP OVMF patches in <TDP-patches-folder>/ovmf/

## 2. Prepare OVMF Tree

Download the source code:

    $ git clone --branch edk2-stable202402 --single-branch https://github.com/tianocore/edk2.git
    $ cd edk2 && git checkout -b ovmf-svsm-tdp

Series#1 is included in the SVSM repo, so no need to download but just apply the patches:

    $ git am --ignore-whitespace <TDP-patches-folder>/ovmf/*\.patch

## 3. Build and Install OVMF

The OVMF compilation process follows the standard procedure without any special requirements.

    $ git submodule update --init --recursive
    $ make -C BaseTools clean && make -C BaseTools
    $ source ./edksetup.sh
    $ build -a X64 -b DEBUG -t GCC5 -D FD_SIZE_2MB -D DEBUG_ON_SERIAL_PORT -D DEBUG_VERBOSE -p OvmfPkg/OvmfPkgX64.dsc

# Setup Coconut-svsm

## 1. Coconut-svsm Source Code With TDP Patches:

The source code with TDP patches is published in github tree at https://github.com/intel-staging/td-partitioning-svsm/tree/svsm-tdp

To download the tree:

    $ git clone https://github.com/intel-staging/td-partitioning-svsm
    $ cd td-partitioning-svsm/
    $ git checkout -b svsm-tdp remotes/origin/svsm-tdp

This svsm-tdp branch is not based on the latest coconut-svsm. The coconut-svsm base is tagged at https://github.com/intel-staging/td-partitioning-svsm/commits/coconut-svsm-base-20240221/

## 2. Prerequisite Setup

Cargo is required to compile the svsm binary. Installation instructions for Cargo can be found in the installation section of the Cargo Book: https://doc.rust-lang.org/cargo/getting-started/installation.html

The coconut-svsm requires a relatively recent version of binutils, and using an outdated version may lead to compilation failures. It is recommended to upgrade binutils to version 2.39 or higher.

## 3. Build Coconut-svsm

To get a debug version svsm.bin, build by:

    $ make

To get a release version svsm.bin, build by:

    $ make RELEASE=1

The svsm.bin will be generated in td-partitioning-svsm/svsm.bin

# Setup TDP Guest Kernel, Initrd And Rootfs Image

Download CentOS stream 9 cloud rootfs image from,
https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-20240311.0.x86_64.qcow2

From the downloaded image extract kernel, initrd using,

    $ sudo modprobe nbd max_part=10
    $ sudo qemu-nbd -c /dev/nbd0 /path/to/downloaded/CentOS9.qcow2
    $ sudo fdisk /dev/nbd0 -l
    $ sudo mount /dev/nbd0p1 /mnt
    $ sudo cp /mnt/boot/initramfs-5.14.0-427.el9.x86_64.img /path/to/launch_script/
    $ sudo cp /mnt/boot/vmlinuz-5.14.0-427.el9.x86_64 /path/to/launch_script/
    $ sudo umount /mnt
    $ sudo qemu-nbd -d /dev/nbd0

# Sample TDP Guest launch script

To launch a TDP guest on top of coconut-svsm, below are required:

    |qemu_system_x86| \\
        -object tdx-guest,id=tdx0,num-l2-vms=1,svsm=on \\
        -machine q35,accel=kvm,kernel-irqchip=split,hpet=off,pic=off,pit=off,sata=off,l2bios=${L2BIOS},confidential-guest-support=tdx0 \\
        -bios OVMF.fd \\
        -initrd ${INITRD} \\
        -kernel $KERNEL \\
        -append "root=/dev/vda1 rw console=hvc0 earlyprintk=ttyS0 loglevel=8 ignore_loglevel nopvspin" \\


Here is a reference script,

    #!/bin/bash

    MEMORY=4G
    CPU=8

    QEMU=/path/to/qemu-system-x86_64 (refer to qemu section)
    KERNEL=/path/to/kernel/bzImage   (see earlier section on Guest kernel, Image and rootfs)
    INITRD=/path/to/initrd           (see earlier section on Guest kernel, Image and rootfs)
    L2BIOS=/path/to/ovmf             (refer to ovmf section)
    BIOS=/path/to/svsm.bin           (refer to coconut-svsm section)

    APPEND="root=/dev/vda1 rw console=hvc0 earlyprintk=ttyS0 loglevel=8 ignore_loglevel nopvspin"

    sudo $QEMU -m $MEMORY \
            -name svsm-tdp,debug-threads=on \
            -nographic \
            -smp ${CPU} \
            -nodefaults \
            -cpu host \
            -bios ${BIOS} \
            -initrd ${INITRD} \
            -kernel $KERNEL \
            -object iothread,id=iothread0 -drive if=none,cache=none,file=${L2_ROOT_DISK},id=drive0 \
            -device virtio-blk-pci,drive=drive0,iommu_platform=true,disable-legacy=on,iothread=iothread0 \
            -netdev user,id=unet,hostfwd=tcp::2224-:22 -device virtio-net-pci,netdev=unet \
            -machine q35,accel=kvm,kernel-irqchip=split,hpet=off,pic=off,pit=off,sata=off,l2bios=${L2BIOS},confidential-guest-support=tdx0 \
            -object tdx-guest,id=tdx0,num-l2-vms=1,svsm=on \
            -append "${APPEND}" \
            -chardev stdio,id=mux,mux=on \
            -device virtio-serial,romfile= \
            -device virtconsole,chardev=mux \
            -serial chardev:mux \
