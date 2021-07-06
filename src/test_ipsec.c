// test_ipsec.c - test IPsec functions

#include "sput.h"

#include "ipsec.h"

static void test_ike_find_last_payload()
{
	unsigned char *buf = "\x00\x00\x00\x00";
	sput_fail_unless(ike_find_last_payload(buf, 3).value == NULL,
			 "buffer too small");
	sput_fail_unless(ike_find_last_payload(buf, 3).error != NULL,
			 "buffer too small (error)");
	sput_fail_unless(ike_find_last_payload(buf, 4).value == NULL,
			 "wrong payload length");
	sput_fail_unless(ike_find_last_payload(buf, 4).error != NULL,
			 "wrong payload length (error)");
	buf = "\x00\x00\x00\x05";
	sput_fail_unless(ike_find_last_payload(buf, 4).value == NULL,
			 "payload exceeds buffer");
	sput_fail_unless(ike_find_last_payload(buf, 4).error != NULL,
			 "payload exceeds buffer (error)");
	buf = "\x00\x00\x00\x04";
	sput_fail_unless(ike_find_last_payload(buf, 4).value == buf,
			 "first buffer");
	sput_fail_unless(ike_find_last_payload(buf, 4).error == NULL,
			 "first buffer (no error)");
}				// test_ike_find_last_payload()

int main()
{
	sput_start_testing();

	sput_enter_suite
	    ("ike_find_last_payload(): Find the last payload in a buffer");
	sput_run_test(test_ike_find_last_payload);
	sput_finish_testing();
	sput_get_return_value();
}				// main() - test_ipsec
