# Builds upstream sched_ext schedulers for an arm64 device from an x86 host:
# clang for the BPF side, bpftool for the skeleton, and the arm64 libraries a
# static loader links against. Those come from bookworm, because trixie's
# libelf.a refers to symbols of a libeu it does not ship and cannot be linked
# statically.
FROM debian:bookworm-slim AS libs
RUN dpkg --add-architecture arm64 && apt-get update && \
    apt-get install -y --no-install-recommends \
    libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64
RUN mkdir -p /arm64/lib /arm64/include && \
    cp /usr/lib/aarch64-linux-gnu/libelf.a /usr/lib/aarch64-linux-gnu/libz.a \
       /usr/lib/aarch64-linux-gnu/libzstd.a /arm64/lib/ && \
    cp /usr/include/libelf.h /usr/include/gelf.h /usr/include/zlib.h /usr/include/zstd.h \
       $(find /usr/include -name zconf.h) /arm64/include/

FROM debian:trixie-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends make clang llvm bpftool \
    gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*
COPY --from=libs /arm64 /arm64
