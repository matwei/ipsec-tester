#!/usr/bin/env bats

ike_sa_init_01() {
  xxd -r t/ike_sa_init-01-req.dump \
  | nc -u -W1 127.0.0.1 500 \
  | xxd > t/ike_sa_init-01-res.dump

  cmp t/ike_sa_init-01-{exp,res}.dump
}

# start itip in background
setup_file() {
  ( local pid=$(exec sh -c 'echo "$PPID"')
    echo $pid > itip.pid
    exec ./itip > itip.out 2>&1
  ) &
  sleep 1
}

# stop itip
teardown_file() {
  kill $(cat itip.pid)
  wait $(cat itip.pid) 2>/dev/null || true
}

@test "IKE_SA_INIT 01" {
  run ike_sa_init_01
  [ "$status" -eq 0 ]
}

# End of tests
