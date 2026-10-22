# Optional offline SQL Server XE reader

This directory contains **helper source only**, not Microsoft assemblies, packages,
runtime, or a license grant. The optional reader uses proprietary
`Microsoft.SqlServer.XEvent.XELite` **2024.2.5.1**. Operator acquisition, current
Microsoft terms, redistribution permission and dependency review are deployment
gates. Tracefall does **not** establish license clearance or accept SQL Server
terms. Do not vendor binaries or NuGet caches into this repository.

A deployment administrator may build `Reader.csproj` using a separately installed
.NET 8 SDK and an independently acquired, pre-restored dependency cache. Perform
restore/build during deployment, never at ingestion. Example after dependencies
are already restored: `dotnet build Reader.csproj --no-restore -c Release`.
Point Tracefall at the **built output directory** (containing its runtimeconfig,
deps and dependency assemblies), not `dotnet run` or a source-build command:

```
TRACEFALL_MSSQL_DOTNET_ROOT=/absolute/runtime-root
TRACEFALL_MSSQL_READER=/absolute/reader-output/Reader.dll
```

The environment is read by the server-side trusted adapter. The native binary
adapter owns its mandatory bubblewrap sandbox, and bypasses the generic Go
parse-worker's inherited address-space/seccomp restrictions. The ingestion
worker concurrency gate still applies. Missing configuration or unavailable
bubblewrap fails closed. Linux bubblewrap is required: other platforms are not
verified. No SQL connection, URL, glob, server discovery, runtime restore or
package download is supported. Runtime/reader directories are trusted deployment
inputs; do not place unrelated sensitive files in them.

The sandbox has no network and only read-only system libraries, the configured
runtime directory, reader output directory and one evidence file; fresh proc/dev
and scratch tmpfs. Parent deadline 40 seconds; helper cancellation 30 seconds;
input 1 GiB; JSONL output 16 MiB; line 1 MiB; events 10,000. Missing header/final,
malformed output, invalid offsets, source hash mismatch, cap or nonzero exit fails
the source rather than accepting partial success. Evidence SHA-256 is checked
before/after and the helper binds the decoded source by hash and size. Checksum
verification is explicitly **true**, unlike the library default. Checksums are
not authenticity or collection-completeness proof.

**No hard total-process memory limit is implemented here.** CoreCLR reserves large
virtual regions: do not copy the Go worker RLIMIT_AS settings. The configured
256 MiB GC heap hard limit is only a managed-heap hint/limit, not a process/cgroup
limit; library allocations and runtime overhead remain outside that guarantee.
Use a separately enforced deployment cgroup/container memory budget when a hard
RSS budget is required. No claim of production hard-memory isolation is made.

Protocol v1: header (schema/version/checksum/source hash/decimal size), event
(decimal ordinal/offsets/size, original event name/UUID/outer timestamp, typed
fields/actions), final (complete/count). Int64/UInt64 and offsets are decimal
strings, bytes base64; internal XEActivityId is retained as rendered value plus
explicit GUID and sequence. Unknown complex types retain typed rendered text,
not a claim of structural decoding. Raw reader records are preserved separately
from summaries; the original binary file remains the primary source.

## Validation gates

- Native `.xel`: offline Linux x64 fixture decode and persisted service-path test,
  gated by `TRACEFALL_REAL_MSSQL_XEL`; SHA-256 pinned in tests. Microsoft fixture
  count reference is 149, **not an independent field-by-field oracle**.
- Native `.sqlaudit`: **experimental / NOT-VERIFIED**. Default refusal; explicit
  `TRACEFALL_MSSQL_AUDIT_EXPERIMENTAL=1` enables the same configured reader for
  controlled validation only. No genuine binary audit fixture has been verified.
  Renaming a XEL fixture is not audit validation and is never used as proof.
- Licensing, real audit fidelity, platform portability, hard memory isolation:
  **NOT VERIFIED**. No SQL Server/container is started by these tests.

Real fixture provenance: microsoft/sqltoolsservice commit
`e78fcdcc646ae56c3ee53b95c49a2521bdb7c10a`,
`test/Microsoft.SqlTools.ServiceLayer.UnitTests/Profiler/TestXel_0.xel`;
SHA-256 `79aad08f9efc149d96f89282a3eea9431aadb63845219e02bb45dfa4e2c11d75`.
Do not commit the fixture or build outputs.
