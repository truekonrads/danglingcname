package dnsdb

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	//	"io/ioutil"
	"net/http"
)

type RRSetAnswer struct {
	Count      uint
	Time_First uint32
	Time_Last  uint32
	RRName     string
	RRType     string
	Bailiwick  string
	Rdata      []string
}
type DNSDBClient struct {
	ApiKey string
}

func (dnsdb *DNSDBClient) Lookup(name string, qtype string) ([]RRSetAnswer, error) {
	client := &http.Client{}
	var req *http.Request
	var resp *http.Response
	var err error
	url := fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/%s/%s/", name, qtype)
	if req, err = http.NewRequest("GET", url, nil); err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-API-Key", dnsdb.ApiKey)
	if resp, err = client.Do(req); err != nil {
		return nil, err
	}
	records := make([]RRSetAnswer, 0)
	switch {
	case resp.StatusCode == 404:
		// return make([]RRSetAnswer, 0), nil
		// this means we got no data back
	case resp.StatusCode == 200:
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			r := RRSetAnswer{}
			b := []byte(scanner.Text())
			if err = json.Unmarshal(b, &r); err != nil {
				return nil, err
			}
			records = append(records, r)
		}
	default:
		return nil, errors.New(fmt.Sprintf("Unexpected status code '%v': %s", resp.StatusCode, resp.Status))
	}
	return records, nil

}
