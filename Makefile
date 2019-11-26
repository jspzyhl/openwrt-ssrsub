
include $(TOPDIR)/rules.mk

PKG_NAME:=ssrsub
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Download decode and update ssr config for your device
	DEPENDS:=+libstdcpp +libuci +bind-dig +wget
endef

define Package/$(PKG_NAME)/description
 Download decode and update shadowsocksr config for your device,
this program is suitable for shadowsocks-libev
(https://github.com/shadowsocks/openwrt-shadowsocks.git)
Usage:
 -f "<filepath>"	Target ssr subscribe file to be decode, this function is aimed at
			resolving files that manually download subscribe file from server
			and manually upload to your device. This param and "-u " is alternative.

 -u "<subscribe URL>"	Target ssr subscribe URL for processing, 
			this param and "-f " is alternative.

 -d "<dns server>"	The dns server for host name resolving, this dns server must be
			reliable, otherwise the resolved host IP will be invalid.

 -x			Use this argument the program will delete temp files after finished.

 -c			Use this argument the program will delete all the ssr server config.

endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/bin/
endef

$(eval $(call BuildPackage,ssrsub))

