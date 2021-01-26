
# Testing itip

The tests in this directory use the
[Bash Automated Testing System (2018)][].

The tests are meant to be run from one directory up like this:

    $ bats -t t
    1..1
    ok 1 IKE_SA_INIT 01

## Requirements

The tests use the following external tools that need to be available:

*   `xxd` from Vim and `nc` from Netcat are used
    to perform some basic network tests.
*   `cmp` from Diffutils is used to compare the output of above tests
    with the expected results.

## Network tests

Basically a network test consists of an IKE requests,
sent with `nc` and the IKE response received by the same process.

The requests are provided as hex dumps that are converted to binary by `xxd`
and feeded via pipe to `nc`.
The same `nc` process writes the answer from the `itip` process
via pipe to another `xxd` process
that converts it to a hexdump.

    xxd -r ike_sa_init-01-req.dump \
     | nc -u -W1 127.0.0.1 500 \
     | xxd > ike_sa_init-01-res.dump

After that you can compare the response with the expected output:

    cmp ike_sa_init-01-{exp,res}.dump

[Bash Automated Testing System (2018)]: https://github.com/bats-core/bats-core

