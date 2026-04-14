use bitflags::bitflags;

bitflags! { // source: https://pkg.go.dev/io/fs#FileMode
    pub struct FileMode: u32 {
        const Dir        = 1 << (32 -  1); // d: is a directory
        const Append     = 1 << (32 -  2); // a: append-only
        const Exclusive  = 1 << (32 -  3); // l: exclusive use
        const Temporary  = 1 << (32 -  4); // T: temporary file; Plan 9 only
        const Symlink    = 1 << (32 -  5); // L: symbolic link
        const Device     = 1 << (32 -  6); // D: device file
        const NamedPipe  = 1 << (32 -  7); // p: named pipe (FIFO)
        const Socket     = 1 << (32 -  8); // S: Unix domain socket
        const Setuid     = 1 << (32 -  9); // u: setuid
        const Setgid     = 1 << (32 - 10); // g: setgid
        const CharDevice = 1 << (32 - 11); // c: Unix character device, when ModeDevice is set
        const Sticky     = 1 << (32 - 12); // t: sticky
        const Irregular  = 1 << (32 - 13); // ?: non-regular file; nothing else is known about this file

        // Mask for the type bits. For regular files, none will be set.
        const Type = Self::Dir.bits() | Self::Symlink.bits() | Self::NamedPipe.bits() |
                     Self::Socket.bits() | Self::Device.bits() | Self::CharDevice.bits() |
                     Self::Irregular.bits();

        const Perm = 0o777; // Unix permission bits
    }
}
