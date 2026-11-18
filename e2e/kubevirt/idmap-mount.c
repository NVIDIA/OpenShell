// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// idmap-mount: remount the filesystem at <path> with an idmap mapping
// on-disk uid/gid <fs_id> <-> mount-visible uid/gid <user_id>: files stored
// as <fs_id> appear owned by <user_id>, and processes running as <user_id>
// create files stored as <fs_id>.
//
// KubeVirt shares filesystem PVCs through virtiofsd, which runs as the
// launcher pod's user (uid/gid 107 by default, runAsNonRoot, no
// capabilities): it cannot switch credentials to an arbitrary guest uid, so
// every guest write EPERMs. An idmapped mount translates the share's
// on-disk ownership (the launcher's fsGroup) into the guest workload's
// uid/gid in both directions: the workload (uid <user_id>) creates files as
// the on-disk uid <fs_id> — the one credential virtiofsd can act as — and
// sees them as its own.
//
// The mapping needs a user namespace owned by a privileged process (guest
// root): a child unshares CLONE_NEWUSER and the parent writes its
// uid_map/gid_map ("<user_id> <fs_id> 1>"). The mount is then idmapped
// through a detached clone re-attached over the original, so no other
// consumer of the path sees an intermediate state.
//
// Build (static musl, as part of the guest image):
//   cc -static -O2 -o idmap-mount idmap-mount.c
//
// Usage: idmap-mount <path> <fs_id> <user_id>   (exit 0 on success)

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000010
#endif

static int mount_setattr_wrapper(int dfd, const char *path, unsigned int flags,
                                 struct mount_attr *attr, size_t size) {
    return (int)syscall(SYS_mount_setattr, dfd, path, flags, attr, size);
}

static int open_tree_wrapper(int dfd, const char *path, unsigned int flags) {
    return (int)syscall(SYS_open_tree, dfd, path, flags);
}

static int move_mount_wrapper(int from_dfd, const char *from_path, int to_dfd,
                              const char *to_path, unsigned int flags) {
    return (int)syscall(SYS_move_mount, from_dfd, from_path, to_dfd, to_path, flags);
}

static int write_proc_file(pid_t child, const char *file, const char *content) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/%s", child, file);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t len = (ssize_t)strlen(content);
    if (write(fd, content, (size_t)len) != len) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int write_map(pid_t child, const char *file, unsigned int inner,
                     unsigned int outer) {
    // Two entries: the workload <-> fs mapping, plus an identity mapping
    // for root. An inode whose owner is unmapped fails directory-permission
    // checks entirely on idmapped mounts (the share root is root-owned), so
    // root must stay mapped even though the workload never acts as it.
    char content[96];
    snprintf(content, sizeof(content), "%u %u 1\n0 0 1\n", inner, outer);
    return write_proc_file(child, file, content);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <path> <fs_id> <user_id>\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    unsigned int fs_id = (unsigned int)strtoul(argv[2], NULL, 10);
    unsigned int user_id = (unsigned int)strtoul(argv[3], NULL, 10);
    if (fs_id == 0 || user_id == 0 || fs_id == user_id) {
        fprintf(stderr, "%s: refusing a trivial or root mapping\n", argv[0]);
        return 2;
    }

    // A child creates the user namespace and signals readiness through a
    // pipe; this process (guest root) holds the privilege to write its
    // maps, and the namespace must stay alive while the mount references
    // it (the child parks until killed).
    int readiness[2];
    if (pipe(readiness) < 0) {
        perror("pipe");
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        close(readiness[0]);
        if (unshare(CLONE_NEWUSER) < 0) {
            (void)!write(readiness[1], "U", 1);
            _exit(1);
        }
        // Ready: the parent can now write the maps.
        (void)!write(readiness[1], "R", 1);
        pause();
        _exit(0);
    }
    close(readiness[1]);
    char ready = 0;
    if (read(readiness[0], &ready, 1) != 1 || ready != 'R') {
        fprintf(stderr, "%s: creating the user namespace failed: %s\n", argv[0],
                ready == 'U' ? "unshare(CLONE_NEWUSER) not permitted" : strerror(errno));
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    // The mount's idmap reads: namespace uid <fs_id> == kernel uid
    // <user_id> — the on-disk id is the namespace side, the process id the
    // kernel side.
    if (write_map(child, "uid_map", fs_id, user_id) < 0) {
        fprintf(stderr, "%s: writing uid_map failed: %s\n", argv[0], strerror(errno));
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    if (write_proc_file(child, "setgroups", "deny") < 0 ||
        write_map(child, "gid_map", fs_id, user_id) < 0) {
        fprintf(stderr, "%s: writing gid_map failed: %s (setgroups must be denied)\n",
                argv[0], strerror(errno));
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    char namespace_path[64];
    snprintf(namespace_path, sizeof(namespace_path), "/proc/%d/ns/user", child);
    int userns_fd = open(namespace_path, O_RDONLY | O_CLOEXEC);
    if (userns_fd < 0) {
        fprintf(stderr, "%s: opening the user namespace failed: %s\n", argv[0],
                strerror(errno));
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    // Clone the mount detached, idmap it, and move it back over the
    // original path.
    int tree_fd = open_tree_wrapper(AT_FDCWD, path, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (tree_fd < 0) {
        fprintf(stderr, "%s: open_tree(%s) failed: %s\n", argv[0], path, strerror(errno));
        kill(child, SIGKILL);
        return 1;
    }
    struct mount_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.attr_set = MOUNT_ATTR_IDMAP;
    attr.userns_fd = (unsigned int)userns_fd;
    if (mount_setattr_wrapper(tree_fd, "", AT_EMPTY_PATH, &attr, sizeof(attr)) < 0) {
        fprintf(stderr, "%s: mount_setattr(IDMAP) failed: %s\n", argv[0], strerror(errno));
        kill(child, SIGKILL);
        return 1;
    }
    int target_fd = open(path, O_PATH | O_CLOEXEC);
    if (target_fd < 0) {
        fprintf(stderr, "%s: open(%s) failed: %s\n", argv[0], path, strerror(errno));
        kill(child, SIGKILL);
        return 1;
    }
    if (move_mount_wrapper(tree_fd, "", target_fd, "",
                           MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) < 0) {
        fprintf(stderr, "%s: move_mount failed: %s\n", argv[0], strerror(errno));
        kill(child, SIGKILL);
        return 1;
    }

    // The idmapped mount holds a reference to the user namespace; the
    // parked child can go.
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
}
