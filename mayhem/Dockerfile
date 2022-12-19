FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake libasound2-dev libudev-dev clang

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_timestamp_user_format.cpp -fsanitize=fuzzer,address /repo/build/src/CMakeFiles/appserver.dir/dtime_now.c.o  /repo/build/external/misc/libmisc.a /repo/build/src/CMakeFiles/direwolf.dir/textcolor.c.o -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_timestamp_user_format
