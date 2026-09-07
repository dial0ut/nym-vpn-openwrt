#!/bin/bash
# OpenWrt image management for the NymVPN test infrastructure.
# Downloads official OpenWrt QEMU images and prepares them for VM boot.

# ---------------------------------------------------------------------------
# Image Download
# ---------------------------------------------------------------------------

# Download the OpenWrt image for a given architecture (cached).
# Usage: download_openwrt_image <arch>
download_openwrt_image() {
    local arch="$1"
    local target="${ARCH_OPENWRT_TARGET[$arch]}"
    local ver="$OPENWRT_VERSION"
    local target_dash="${target//\//-}"
    local base_url="${OPENWRT_MIRROR}/${ver}/targets/${target}"
    local image_type="${ARCH_IMAGE_TYPE[$arch]}"

    ensure_dirs

    if [[ "$image_type" == "disk" ]]; then
        local dest="${IMAGE_DIR}/${arch}.img"
        if [[ -f "$dest" ]]; then
            log_info "[$arch] Image already cached: $dest"
            return 0
        fi

        local filename
        case "$arch" in
            x86_64)
                filename="openwrt-${ver}-x86-64-generic-ext4-combined.img.gz"
                ;;
            i686)
                filename="openwrt-${ver}-x86-generic-generic-ext4-combined.img.gz"
                ;;
            aarch64)
                filename="openwrt-${ver}-armsr-armv8-generic-ext4-combined.img.gz"
                ;;
            armv7)
                filename="openwrt-${ver}-armsr-armv7-generic-ext4-combined.img.gz"
                ;;
            riscv64)
                filename="openwrt-${ver}-${target_dash}-generic-ext4-combined.img.gz"
                ;;
            *)
                die "[$arch] Unknown disk image pattern"
                ;;
        esac

        log_info "[$arch] Downloading ${filename}..."
        wget -q "${base_url}/${filename}" -O "${dest}.gz" || \
            die "[$arch] Failed to download image from ${base_url}/${filename}"
        gunzip -f "${dest}.gz"

        # Resize disk to 512M so there's room for package installation
        if command -v qemu-img &>/dev/null; then
            qemu-img resize "$dest" 512M 2>/dev/null || true
        fi

        log_info "[$arch] Image ready: $dest"

    elif [[ "$image_type" == "initramfs" ]]; then
        local dest="${IMAGE_DIR}/${arch}.elf"
        if [[ -f "$dest" ]]; then
            log_info "[$arch] Kernel already cached: $dest"
            return 0
        fi

        local endian filename
        case "$arch" in
            mips)   endian="be" ;;
            mipsel) endian="le" ;;
            *)      die "[$arch] Unknown initramfs arch" ;;
        esac
        filename="openwrt-${ver}-malta-${endian}-vmlinux-initramfs.elf"

        log_info "[$arch] Downloading ${filename}..."
        wget -q "${base_url}/${filename}" -O "$dest" || \
            die "[$arch] Failed to download kernel from ${base_url}/${filename}"

        log_info "[$arch] Kernel ready: $dest"
    fi
}

# Download images for all architectures.
# Usage: download_all_images
download_all_images() {
    for arch in "${ARCHS[@]}"; do
        download_openwrt_image "$arch"
    done
}

# ---------------------------------------------------------------------------
# Image Preparation (per test run)
# ---------------------------------------------------------------------------

# Copy the cached image to scratch for a fresh test run.
# Usage: prepare_vm_image <arch>
prepare_vm_image() {
    local arch="$1"
    local image_type="${ARCH_IMAGE_TYPE[$arch]}"

    ensure_dirs

    if [[ "$image_type" == "disk" ]]; then
        local src="${IMAGE_DIR}/${arch}.img"
        local dst="${SCRATCH_DIR}/${arch}.img"
        [[ -f "$src" ]] || die "[$arch] Cached image not found: $src"
        log_info "[$arch] Preparing fresh disk image..."
        cp "$src" "$dst"
    elif [[ "$image_type" == "initramfs" ]]; then
        local src="${IMAGE_DIR}/${arch}.elf"
        local dst="${SCRATCH_DIR}/${arch}.elf"
        [[ -f "$src" ]] || die "[$arch] Cached kernel not found: $src"
        cp "$src" "$dst"
    fi
}

# ---------------------------------------------------------------------------
# First-Boot Setup
# ---------------------------------------------------------------------------

# Configure a freshly booted OpenWrt VM for SSH access.
# Fresh OpenWrt has an empty root password, so SSH should work immediately
# on OpenWrt 23.05+ (dropbear allows empty password by default on LAN).
# We set a password and configure basic networking for reliable access.
# Usage: setup_openwrt_vm <arch>
setup_openwrt_vm() {
    local arch="$1"

    log_info "[$arch] Configuring OpenWrt first-boot..."

    # Set root password (empty password is allowed but fragile)
    vm_ssh "$arch" "echo 'root:nymtest' | chpasswd" 2>/dev/null || true

    # Ensure time is roughly correct (TLS validation needs this)
    local now
    now=$(date -u +%Y%m%d%H%M)
    vm_ssh "$arch" "date -u -s '${now}'" 2>/dev/null || true

    # For emulated VMs with user-mode networking, DNS is at 10.0.2.3
    if [[ "${ARCH_KVM[$arch]}" != "yes" ]]; then
        vm_ssh "$arch" "
            # Ensure DNS resolution works through QEMU user-mode NAT
            uci set network.wan=interface
            uci set network.wan.proto='dhcp'
            uci set network.wan.device='eth0'
            uci commit network
            /etc/init.d/network restart
        " 2>/dev/null || true
        # Give network time to come up
        sleep 5
    fi

    # Verify connectivity
    if vm_ssh "$arch" "wget -qO /dev/null http://downloads.openwrt.org/ 2>&1" >/dev/null 2>&1; then
        log_info "[$arch] Internet connectivity verified"
    else
        log_warn "[$arch] Internet connectivity check failed (may still work)"
    fi
}

# ---------------------------------------------------------------------------
# Package Installation
# ---------------------------------------------------------------------------

# Install a NymVPN package on a test VM.
# Usage: install_package <arch> <package_path>
#   package_path: local path to .ipk or .apk file on the Proxmox host
install_package_file() {
    local arch="$1"
    local pkg_path="$2"
    local filename
    filename=$(basename "$pkg_path")
    local ext="${filename##*.}"

    log_info "[$arch] Installing package: $filename"

    # Transfer package to VM
    vm_scp "$arch" "$pkg_path" "/tmp/${filename}"

    case "$ext" in
        ipk)
            vm_ssh "$arch" "opkg update 2>/dev/null; opkg install /tmp/${filename}" || \
                die "[$arch] opkg install failed"
            ;;
        apk)
            vm_ssh "$arch" "apk add --allow-untrusted /tmp/${filename}" || \
                die "[$arch] apk install failed"
            ;;
        *)
            die "[$arch] Unknown package format: $ext"
            ;;
    esac

    log_info "[$arch] Package installed successfully"
}

# Install NymVPN from the package feed.
# Usage: install_package_feed <arch>
install_package_feed() {
    local arch="$1"
    local pkg_arch="${ARCH_PKG_ARCH[$arch]}"

    log_info "[$arch] Installing from feed (arch: $pkg_arch)..."

    # Add the NymVPN feed
    vm_ssh "$arch" "
        echo 'src/gz nymvpn https://packages.dial0ut.org/opkg/${pkg_arch}' >> /etc/opkg/customfeeds.conf
        opkg update
        opkg install nym-vpn
    " || die "[$arch] Feed install failed"

    log_info "[$arch] Package installed from feed"
}

# Install NymVPN from a GitHub release.
# Usage: install_package_release <arch> <tag>
install_package_release() {
    local arch="$1"
    local tag="$2"
    local pkg_arch="${ARCH_PKG_ARCH[$arch]}"

    log_info "[$arch] Downloading package from release $tag..."

    local pkg_name="nym-vpn_${tag#v}_${pkg_arch}.ipk"
    local download_dir="${SCRATCH_DIR}/packages"
    mkdir -p "$download_dir"

    if [[ ! -f "${download_dir}/${pkg_name}" ]]; then
        gh release download "$tag" \
            --repo dial0ut/nym-vpn-openwrt \
            --pattern "$pkg_name" \
            --dir "$download_dir" || \
            die "[$arch] Failed to download $pkg_name from release $tag"
    fi

    install_package_file "$arch" "${download_dir}/${pkg_name}"
}
