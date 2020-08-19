
# IPsec Tester

This is a program to analyze IPsec IKEv2 traffic.

It interprets IPsec messages and acts on them.

The goal of this program is
to better understand the function of existing IPsec implementations.

# Installation

## Prerequisites

This program makes use of the [Zlog library][zlog] for flexible logging.

The cryptographic functions are provided by [Libgcrypt][libgcrypt].

## Installing

The program make use of [GNU Autoconf][autoconf].
After having installed the development files
of the Zlog library and Libgcrypt,
you may clone the repository,
reconfigure the Makefile and compile the program.

    git clone https://github.com/matwei/ipsec-tester.git
    cd ipsec-tester
    autoreconf -i
    ./configure
    make

If you want set the *CAP_NET_BIND_SERVICE* capability,
you can use the `test-capabilities` target of the Makefile

    make test-capabilities

# Usage

To use the program just call it and watch the output.

    ./itip

## Configuration

At the moment the only configuration is through the file zlog.conf,
which configures the logging of the Zlog library.

You can define a different log format and send the logs to different targets.

# Security

Because this program needs to bind to UDP port 500 and raw sockets,
it needs elevated privileges.

If your system supports POSIX capabilities,
it is recommended to give the compiled program
the *CAP_NET_BIND_SERVICE* capability.

The Makefile provides this capability
when called as `make test-capabilities`:

    sudo setcap cap_net_bind_service=ep $(bin_PROGRAMS)

[autoconf]: https://www.gnu.org/software/autoconf/
[libgcrypt]: https://gnupg.org/software/libgcrypt/
[zlog]: https://hardysimpson.github.io/zlog/
