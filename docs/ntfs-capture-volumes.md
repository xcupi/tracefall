# Read-only NTFS volumes with omitted DOS boot fields

Tracefall accepts a narrowly identified NTFS filesystem even when the first
three bytes (DOS boot jump) and bytes 510–511 (DOS boot signature) of its volume
boot sector are all zero. This is filesystem access, not a determination that a
volume is or was bootable, a complete physical disk, or a particular kind of
acquisition. The original bytes are never patched.

Acceptance requires the exact NTFS OEM identifier, all existing geometry and
bounds checks, successful MFT bootstrap including data-run coverage and update
sequence checks, and a valid live root record. The root must be a base directory
record named `.` whose parent reference points to itself with the current
sequence number. These extra root checks apply only to the omitted-fields
branch; ordinary signed-volume behavior is unchanged.

A partial or nonzero invalid signature remains unsupported. A missing signature
with a nonzero boot jump is not accepted by this branch. OEM bytes alone are
insufficient. Geometry, bootstrap or root corruption remains an error; other
record damage found during enumeration continues to be disclosed in walk and
image-report statistics. Successful opening is not a guarantee that every file
or stream is readable.

`ntfsvol.Info.Warnings` exposes the observed omission. Disk discovery persists
that warning, qualified by partition number, in `diskimage.json` notes; the
existing disk-image report summary carries those notes into the forensic report.
The warning makes no acquisition, incident, host or timestamp attribution.
Existing compression/encryption, shadow-copy, journal-replay and backup-boot-sector
limitations are unchanged.

Regression fixtures come from the independently generated mkntfs/ntfs-3g image
and its content manifest. Tests zero only the two DOS boot fields in an isolated
copy, check every manifest file's size and SHA-256, exercise malformed marker,
geometry, MFT and root negative controls, and compare complete API catalog
selection and persisted/report warnings against the unchanged signed fixture.
