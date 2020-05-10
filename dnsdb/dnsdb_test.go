package dnsdb

import (
	//. "github.com/truekonrads/danglingcname/dnsdb"
	"os"
	"testing"
)

const LOOKUP_DOMAIN string = "www.golang.org"
const LOOKUP_QTYPE string = "ANY"

func TestLookup(t *testing.T) {
	key := os.Getenv("DNSDB_KEY")
	if len(key) == 0 {
		t.Skip("DNSDB_KEY not found, skipping test")
	}
	dc := DNSDBClient{ApiKey: key}
	var res []RRSetAnswer
	var err error
	if res, err = dc.Lookup(LOOKUP_DOMAIN, LOOKUP_QTYPE); err != nil {

		t.Fatalf("Unable to lookup %s (%s): %v", LOOKUP_DOMAIN, LOOKUP_QTYPE, err)
	}
	if len(res) == 0 {
		t.Fatalf("Zero records found")
	}
	if res[0].RRName != LOOKUP_DOMAIN+"." {
		t.Fatalf("Unexpected record: %v", res[0])
	}
	if len(res[0].Rdata) == 0 {
		t.Fatalf("Empty Rdata")
	}
	t.Log(res[0])
}
