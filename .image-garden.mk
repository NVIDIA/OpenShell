# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Ubuntu 24.04 instances

# snapd-no-docker: snapd only, no docker.
# install.sh chooses the "snap" install path.
$(eval $(call define-instance,ubuntu-cloud-24.04,snapd-no-docker))
define UBUNTU_24.04@snapd-no-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- snap wait system seed.loaded
- snap install snapd
packages:
- snapd
endef

# snapd-classic-docker: snapd + native docker (docker.io deb package).
# install.sh chooses the "classic" install path because native docker is detected.
$(eval $(call define-instance,ubuntu-cloud-24.04,snapd-classic-docker))
define UBUNTU_24.04@snapd-classic-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- snap wait system seed.loaded
- snap install snapd
packages:
- snapd
- docker.io
endef

# no-snapd: snapd removed, docker.io installed.
# install.sh chooses the "classic" install path because snapd is absent.
$(eval $(call define-instance,ubuntu-cloud-24.04,no-snapd))
define UBUNTU_24.04@no-snapd_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- apt-get purge -y snapd
packages:
- docker.io
endef

# Ubuntu 26.04 instances

# snapd-no-docker: snapd only, no docker.
# install.sh chooses the "snap" install path.
$(eval $(call define-instance,ubuntu-cloud-26.04,snapd-no-docker))
define UBUNTU_26.04@snapd-no-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- snap wait system seed.loaded
- snap install snapd
packages:
- snapd
endef

# snapd-classic-docker: snapd + native docker (docker.io deb package).
# install.sh chooses the "classic" install path because native docker is detected.
$(eval $(call define-instance,ubuntu-cloud-26.04,snapd-classic-docker))
define UBUNTU_26.04@snapd-classic-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- snap wait system seed.loaded
- snap install snapd
packages:
- snapd
- docker.io
endef

# no-snapd: snapd removed, docker.io installed.
# install.sh chooses the "classic" install path because snapd is absent.
$(eval $(call define-instance,ubuntu-cloud-26.04,no-snapd))
define UBUNTU_26.04@no-snapd_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- apt-get purge -y snapd
packages:
- docker.io
endef

# Debian 13 instances

# snapd-no-docker: snapd only, no docker.
# install.sh chooses the "snap" install path.
$(eval $(call define-instance,debian-cloud-13,snapd-no-docker))
define DEBIAN_13@snapd-no-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- snap wait system seed.loaded
- snap install snapd
packages:
- snapd
endef

# snapd-classic-docker: snapd + native docker (docker.io deb package).
# install.sh chooses the "classic" install path because native docker is detected.
$(eval $(call define-instance,debian-cloud-13,snapd-classic-docker))
define DEBIAN_13@snapd-classic-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- snap wait system seed.loaded
- snap install snapd
packages:
- snapd
- docker.io
endef

# no-snapd: snapd removed, docker.io installed.
# install.sh chooses the "classic" install path because snapd is absent.
$(eval $(call define-instance,debian-cloud-13,no-snapd))
define DEBIAN_13@no-snapd_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- apt-get purge -y snapd
packages:
- docker.io
endef

# Fedora 44 instances

# snapd-no-docker: snapd only, no docker.
# install.sh chooses the "snap" install path.
$(eval $(call define-instance,fedora-cloud-44,snapd-no-docker))
define FEDORA_44@snapd-no-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- systemctl enable --now snapd.socket
- snap wait system seed.loaded
packages:
- snapd
endef

# snapd-docker: snapd + native docker (docker rpm package).
# install.sh chooses the "classic" install path because native docker is detected.
$(eval $(call define-instance,fedora-cloud-44,snapd-docker))
define FEDORA_44@snapd-docker_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- systemctl enable --now snapd.socket
- snap wait system seed.loaded
packages:
- snapd
- docker
endef

# no-snapd: just docker, no snapd.
# install.sh chooses the "classic" install path because snapd is absent.
$(eval $(call define-instance,fedora-cloud-44,no-snapd))
define FEDORA_44@no-snapd_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
packages:
- docker
endef
