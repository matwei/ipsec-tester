
# IPsec Tester

This is a program to analyze IPsec IKEv2 traffic.

It interprets IPsec messages and acts on them.

The goal of this program is
to better understand the function of existing IPsec implementations.

# Installation

## Prerequisites

This program makes use of the [Zlog library][zlog] for flexible logging.

The cryptographic functions are provided by [Libgcrypt][libgcrypt].

### Zlog library

To install the library you got to
https://github.com/HardySimpson/zlog/releases
and download a suitable version.
Version 1.2.14 is known to work,
any later version will probably work as well.

After you downloaded the sources
you extract the archive,
change into the directory,
compile and install the library.

    tar -zxvf zlog-1.2.14.tar.gz
    cd zlog-1.2.14
    make
    sudo make install

After you have installed the library
you have to update the cache of the dynamic linker
so that it can be found by the running programm.
Just call

    ldconfig -v

and make sure that the library is found.

### Libgcrypt

Libgcrypt is easier to install
because it is available on many Linux distributions.
Make sure to install the development package.

On Ubuntu 18.04 you can install it like this:

    apt install libgcrypt20-dev

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
you can use the `set-capabilities` target of the Makefile

    make set-capabilities

# Usage

To use the program just call it
and watch the output while a VPN gateway is trying
to contact your machine.

    ./itip

## Configuration

At the moment the only configuration is through the file zlog.conf,
which configures the logging of the Zlog library.
You can define a different log format and send the logs to different targets.

Please look up the [zlog User's Guide][zlogug]
for details about the logging configuration.

# Security

Because this program needs to bind to UDP port 500 and raw sockets,
it needs elevated privileges.

If your system supports POSIX capabilities,
it is recommended to give the compiled program
the *CAP_NET_BIND_SERVICE* capability.

The Makefile provides this capability
when called as `make test-capabilities`:

    sudo setcap cap_net_bind_service=ep $(bin_PROGRAMS)

# Testing

## Module tests with Sput

The programm `test_ipsec`,
that is compiled by calling the make target `test_ipsec`,
performs some module tests when invoked.
This program uses the [Sput Unit Testing Framework for C/C++][sput].

## Shell tests using BATS

There are system tests of the compiled program in directory *t/*.
These tests use [BATS][] (the Bash Automated Testing System)
and need the programs `nc` (Netcat), `xxd` (Vim) and `cmp` (Diffutils)
to execute the tests.
You invoke these tests like this:

    bats t

or

    bats -t t

Unfortunately there are versions of BATS that don't work with these tests.
Especially *bat-core-1.1.0* that is shipped with Ubuntu 20.04
will not work with these tests. Versions *1.2.1* and *1.3.0* are known to work.

[autoconf]: https://www.gnu.org/software/autoconf/
[BATS]: https://github.com/bats-core/bats-core
[libgcrypt]: https://gnupg.org/software/libgcrypt/
[sput]: https://www.use-strict.de/sput-unit-testing/
[zlog]: https://hardysimpson.github.io/zlog/
[zlogug]: http://hardysimpson.github.io/zlog/UsersGuide-EN.html
