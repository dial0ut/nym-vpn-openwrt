# Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
# SPDX-License-Identifier: GPL-3.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-nym-vpn
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-3.0-only
PKG_MAINTAINER:=Nym Technologies SA <contact@nymtech.net>

LUCI_TITLE:=LuCI support for Nym VPN
LUCI_DESCRIPTION:=Web interface for managing Nym VPN connections
LUCI_DEPENDS:=+rpcd +luci-base
LUCI_PKGARCH:=all

define Package/luci-app-nym-vpn/conffiles
/etc/config/nym-vpn
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
