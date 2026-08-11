"""Pinned cloud images and supported test-guest variants."""

TEST_GUEST_BASE_IMAGES = [
    struct(
        architecture = "aarch64",
        distro = "ubuntu",
        downloaded_file_path = "ubuntu-24.04-aarch64.qcow2",
        integrity = "sha256-meHUgrlY5r/QGDpMSM5twzTgmj4ppFYPb1/4VZPQnR0=",
        os_id = "ubuntu",
        os_version = "24.04",
        package_family = "deb",
        repo_name = "test_guest_ubuntu_aarch64",
        url = "https://cloud-images.ubuntu.com/releases/noble/release-20260225/ubuntu-24.04-server-cloudimg-arm64.img",
    ),
    struct(
        architecture = "x86_64",
        distro = "ubuntu",
        downloaded_file_path = "ubuntu-24.04-x86_64.qcow2",
        integrity = "sha256-eqbZ9eijpVx0RbE40xpz0Rh4cSEbK32p2i4abL8WmyE=",
        os_id = "ubuntu",
        os_version = "24.04",
        package_family = "deb",
        repo_name = "test_guest_ubuntu_x86_64",
        url = "https://cloud-images.ubuntu.com/releases/noble/release-20260225/ubuntu-24.04-server-cloudimg-amd64.img",
    ),
    struct(
        architecture = "aarch64",
        distro = "centos",
        downloaded_file_path = "centos-stream-10-aarch64.qcow2",
        integrity = "sha256-55IuyMUvsbpvqgug2S7w6JpLCSIpR4HJVkuMch60Rag=",
        os_id = "centos",
        os_version = "10",
        package_family = "rpm",
        repo_name = "test_guest_centos_aarch64",
        url = "https://cloud.centos.org/centos/10-stream/aarch64/images/CentOS-Stream-GenericCloud-10-20260720.0.aarch64.qcow2",
    ),
    struct(
        architecture = "x86_64",
        distro = "centos",
        downloaded_file_path = "centos-stream-10-x86_64.qcow2",
        integrity = "sha256-k3lpRd9eVJUr4hyoUGfwyfOxGi3W7iFjFU/ZdIxMQdc=",
        os_id = "centos",
        os_version = "10",
        package_family = "rpm",
        repo_name = "test_guest_centos_x86_64",
        url = "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260720.0.x86_64.qcow2",
    ),
    struct(
        architecture = "aarch64",
        distro = "fedora",
        downloaded_file_path = "fedora-44-aarch64.qcow2",
        integrity = "sha256-VcYKO4DTYWoIcFr9BFnnX+nwPFSrp6RuQAKkGnL6DVs=",
        os_id = "fedora",
        os_version = "44",
        package_family = "rpm",
        repo_name = "test_guest_fedora_aarch64",
        url = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-44-1.7.aarch64.qcow2",
    ),
    struct(
        architecture = "x86_64",
        distro = "fedora",
        downloaded_file_path = "fedora-44-x86_64.qcow2",
        integrity = "sha256-KGgP5bNxpaguv0OjGSbghqFo5ZlJ0DlpxQk+cHH5C38=",
        os_id = "fedora",
        os_version = "44",
        package_family = "rpm",
        repo_name = "test_guest_fedora_x86_64",
        url = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2",
    ),
    struct(
        architecture = "aarch64",
        distro = "rocky",
        downloaded_file_path = "rocky-9-aarch64.qcow2",
        integrity = "sha256-JGkqRE8fC4u5U3XDjItD+AmaEVNHYjaRviwzC0DIof4=",
        os_id = "rocky",
        os_version = "9",
        package_family = "rpm",
        repo_name = "test_guest_rocky_aarch64",
        url = "https://download.rockylinux.org/pub/rocky/9/images/aarch64/Rocky-9-GenericCloud-Base-9.8-20260525.0.aarch64.qcow2",
    ),
    struct(
        architecture = "x86_64",
        distro = "rocky",
        downloaded_file_path = "rocky-9-x86_64.qcow2",
        integrity = "sha256-ksIGzG95DGFYMkfu/oeJD4goQgZiwXys8kfOx4q07sg=",
        os_id = "rocky",
        os_version = "9",
        package_family = "rpm",
        repo_name = "test_guest_rocky_x86_64",
        url = "https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2",
    ),
]

TEST_GUEST_VARIANTS = [
    struct(configurations = [], distro = "ubuntu", name = "ubuntu"),
    struct(configurations = ["docker"], distro = "ubuntu", name = "ubuntu_docker"),
    struct(configurations = ["podman"], distro = "ubuntu", name = "ubuntu_podman"),
    struct(configurations = [], distro = "centos", name = "centos"),
    struct(configurations = ["podman"], distro = "centos", name = "centos_podman"),
    struct(configurations = ["selinux"], distro = "centos", name = "centos_selinux"),
    struct(configurations = ["podman", "selinux"], distro = "centos", name = "centos_podman_selinux"),
    struct(configurations = [], distro = "fedora", name = "fedora"),
    struct(configurations = ["podman"], distro = "fedora", name = "fedora_podman"),
    struct(configurations = ["selinux"], distro = "fedora", name = "fedora_selinux"),
    struct(configurations = ["podman", "selinux"], distro = "fedora", name = "fedora_podman_selinux"),
    struct(configurations = [], distro = "rocky", name = "rocky"),
    struct(configurations = ["docker"], distro = "rocky", name = "rocky_docker"),
    struct(configurations = ["podman"], distro = "rocky", name = "rocky_podman"),
    struct(configurations = ["selinux"], distro = "rocky", name = "rocky_selinux"),
    struct(configurations = ["docker", "selinux"], distro = "rocky", name = "rocky_docker_selinux"),
    struct(configurations = ["podman", "selinux"], distro = "rocky", name = "rocky_podman_selinux"),
]

def declare_test_guest_targets(base_image_rule, variant_macro):
    """Declare base-image providers and the supported prepared-image matrix."""
    by_distro = {}
    for image in TEST_GUEST_BASE_IMAGES:
        target_name = "base_{}_{}".format(image.distro, image.architecture)
        base_image_rule(
            name = target_name,
            architecture = image.architecture,
            distro = image.distro,
            image = "@{}//file".format(image.repo_name),
            integrity = image.integrity,
            os_id = image.os_id,
            os_version = image.os_version,
            package_family = image.package_family,
            url = image.url,
            visibility = ["//visibility:private"],
        )
        by_distro.setdefault(image.distro, {})[image.architecture] = ":" + target_name

    for variant in TEST_GUEST_VARIANTS:
        variant_macro(
            name = variant.name,
            base_image = select({
                ":aarch64": by_distro[variant.distro]["aarch64"],
                ":x86_64": by_distro[variant.distro]["x86_64"],
            }),
            configurations = [":configuration/{}.yml".format(name) for name in variant.configurations],
        )
