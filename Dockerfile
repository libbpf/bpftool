# With this Dockerfile, you can create a container image:
#     $ docker build -f Dockerfile -t bpftool .
# And then use it:
#     $ docker run --rm -ti --privileged --pid=host bpftool prog

FROM ubuntu:22.04 as builder

RUN \
	export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get -y install --no-install-recommends \
		build-essential \
		libelf-dev \
		libz-dev \
		libcap-dev \
		clang llvm llvm-dev lld \
		binutils-dev \
		pkg-config && \
	rm -rf /var/lib/apt/lists/*

COPY . /src
RUN cd /src/src && \
	make clean && \
	make -j $(nproc)

FROM ubuntu:22.04
RUN \
	export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get -y install --no-install-recommends \
		libelf1 \
		llvm && \
	rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/src/bpftool /bin/bpftool

ENTRYPOINT ["/bin/bpftool"]
