FROM ubuntu:16.04
MAINTAINER Franziskus Kiefer <franziskuskiefer@gmail.com>

# Pinned version of HACL* (F* and KreMLin are pinned as submodules)
ENV haclrepo https://github.com/mitls/hacl-star.git

# Define versions of dependencies
ENV opamv 4.04.2
ENV haclversion 06b4c54b101b2b80dda1e1d4f6fc5d859b8c5d0b

# Create user.
RUN useradd -ms /bin/bash worker
WORKDIR /home/worker

# Install required packages and set versions
# Build F*, HACL*. Install a few more dependencies.
ENV OPAMYES true
ENV PATH "/home/worker/hacl-star/dependencies/z3/bin:/home/worker/hacl-star/dependencies/FStar/bin/:$PATH"
ADD setup.sh /tmp/setup.sh
RUN bash /tmp/setup.sh

USER worker
