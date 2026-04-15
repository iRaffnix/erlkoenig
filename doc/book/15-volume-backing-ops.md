# Chapter 15 — Volume Backing Operations

Chapter 8 described persistent volumes from the DSL side. This
chapter is the operator view: how the host filesystem that backs
those volumes is set up, verified, resized, and migrated. The
procedure runs once per host, before the first container with a
`volume` clause starts.

## Why XFS on a loop file

The host needs a separate filesystem at
`/var/lib/erlkoenig/volumes/`. A separate filesystem provides the
mount boundary (`nosuid`, `nodev`, `noexec` actually take effect),
the isolation (one container filling the volume doesn't fill the
root filesystem), and the features erlkoenig relies on (reflink for
cheap clones, project quota for per-volume limits).

On single-disk hosts — VMs, laptops, low-cost cloud instances — a
dedicated partition is often not available. A loop-mounted XFS
image file provides the same filesystem-level guarantees. The trade
is transparent: the image lives on the root filesystem as a regular
file, so it shares the underlying block device with the root, but
everything above the mount point behaves identically to a real
partition. Reflink works, project quota works, mount flags work,
inode separation works.

The migration story to a real partition or a different filesystem
(bcachefs, for example) comes to *unmount the old backing, mount the
new backing at the same path*. DSL, containers, and wire protocol
see no change.

## Setup procedure

Run once, as root, on each host:

```bash
# 1. Create the image file (sparse — actual usage grows on write).
truncate -s 10G /var/lib/erlkoenig-volumes.img

# 2. Format as XFS with reflink enabled. Reflink is mandatory for
#    cheap snapshots and fast clone operations.
mkfs.xfs -m reflink=1 -L ek-volumes /var/lib/erlkoenig-volumes.img

# 3. Ensure the mount point exists.
mkdir -p /var/lib/erlkoenig/volumes

# 4. Mount via loop, with security and quota flags enabled.
#    prjquota has to be set at mount time — XFS cannot turn on
#    project quotas on an already-mounted filesystem.
mount -o loop,nosuid,nodev,prjquota \
    /var/lib/erlkoenig-volumes.img \
    /var/lib/erlkoenig/volumes

# 5. Set ownership and mode on the mount point. The erlkoenig
#    service group needs to read; others do not.
chown root:erlkoenig /var/lib/erlkoenig/volumes
chmod 750 /var/lib/erlkoenig/volumes

# 6. Persist the mount across reboots. `nofail` prevents boot hang
#    if the image is ever missing.
echo '/var/lib/erlkoenig-volumes.img /var/lib/erlkoenig/volumes xfs \
      loop,nosuid,nodev,prjquota,nofail 0 2' >> /etc/fstab

# 7. Sanity check — unmount and let fstab bring it back.
umount /var/lib/erlkoenig/volumes
mount -a
mount | grep erlkoenig-volumes
```

The last command should print a single line matching the fstab
entry with a mount type of `xfs` and the flags `rw,nosuid,nodev`.

## Verification

Two checks confirm that reflink and project quotas are actually
live. Both are cheap and idempotent.

**Reflink round-trip.** Create a 50 MB file, clone it with
`cp --reflink=always`, then confirm that disk usage did not change:

```bash
cd /var/lib/erlkoenig/volumes
dd if=/dev/urandom of=src.bin bs=1M count=50 status=none
df -h . | tail -1                              # note the Used column
cp --reflink=always src.bin clone.bin
df -h . | tail -1                              # same Used value
ls -lh src.bin clone.bin                       # both 50 MB
rm -f src.bin clone.bin
```

If the `df` value is unchanged between the two readings, reflink is
working — the clone shares the underlying extents with the source.
If it doubled, reflink is not active and the `mkfs.xfs` command was
run without `reflink=1`.

**Project quota state.** `xfs_quota` exposes the on/off state of the
accounting and enforcement subsystems:

```bash
xfs_quota -x -c "state -p" /var/lib/erlkoenig/volumes
```

A healthy mount shows `Accounting: ON` and `Enforcement: ON` for
project quotas. Missing or off means `prjquota` was not in the
mount options.

## Sizing

The 10 GB default is for development. Production sizing depends on
what the containers write:

| Workload class          | Rough sizing                                        |
|-------------------------|-----------------------------------------------------|
| Dev / stage             | 10 GB                                               |
| Small production        | 50–100 GB (moderate logs and uploads)               |
| Log-heavy services      | 1 GB/day × retention × service count                |
| Upload-heavy services   | p99 user × p99 file size × peak concurrency         |
| Databases               | DB working set × replicas + 20 % for reflink snapshots |

Sparse images grow on write, so an oversized allocation costs
nothing until data arrives.

## Resizing

Growing works online. Shrinking is not supported by XFS — don't try.

```bash
truncate -s 20G /var/lib/erlkoenig-volumes.img
losetup -c $(losetup -j /var/lib/erlkoenig-volumes.img | cut -d: -f1)
xfs_growfs /var/lib/erlkoenig/volumes
```

The `truncate` allocates the additional sparse space. `losetup -c`
re-reads the underlying file size into the loop device. `xfs_growfs`
extends the filesystem to fill it.

## Migration to a real partition

When the host gains a dedicated disk or partition, migration is a
copy plus a config swap:

```bash
# 1. Format the new disk.
mkfs.xfs -m reflink=1 /dev/nvme1n1p1

# 2. Mount it temporarily.
mkdir /mnt/ek-new
mount -o nosuid,nodev,prjquota /dev/nvme1n1p1 /mnt/ek-new

# 3. Copy everything preserving xattrs, ACLs, hardlinks, sparse
#    extents. Containers should be stopped for a clean copy.
rsync -aHAXS /var/lib/erlkoenig/volumes/ /mnt/ek-new/

# 4. Swap the mount target. Update fstab to point at /dev/nvme1n1p1
#    instead of the image, then remount.
umount /mnt/ek-new
umount /var/lib/erlkoenig/volumes
vi /etc/fstab      # replace the loop line with a device line
mount -a

# 5. Verify the new backing.
mount | grep erlkoenig/volumes
```

The image file can be removed afterwards. Containers see no change
because `/var/lib/erlkoenig/volumes/<uuid>/` is where both the old
loop and the new device put the volumes — the mount point is the
interface.

## Cross-reference

Chapter 8 is the DSL truth for users (how `volume "..."` is
written). This chapter is the operator truth (how the host
filesystem is prepared). Both describe the same data — Chapter 8
from the container side, this chapter from the host side. The
mount-options semantics (nosuid, noexec, propagation) bridge the two
and are documented in Chapter 8.
