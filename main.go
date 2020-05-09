package main

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"strings"
	//"net/http"
	//"os"
)

import "errors"

const DNSSERVER string = "172.31.0.1:53"

func lookupCNAME(target string, server string) (result []string, ok bool) {
	return lookupRecord(target, server, dns.TypeCNAME)
}
func lookupA(target string, server string) (result []string, ok bool) {
	return lookupRecord(target, server, dns.TypeA)
}
func lookupRecord(target string, server string, qtype uint16) (result []string, ok bool) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(target, qtype)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, server)
	if err != nil {
		fmt.Println(err)
		return nil, false

	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, true
	}
	for _, a := range r.Answer {
		h := a.Header()
		if h.Rrtype == qtype {
			if x, ok := a.(*dns.CNAME); ok {
				result = append(result, x.Target)
			}
			if x, ok := a.(*dns.A); ok {
				result = append(result, x.A.String())
			}

		}
	}
	return result, true
}

type CRTRecord struct {
	// "issuer_ca_id": 1449,
	// "issuer_name": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Secure Server CA - G4",
	// "name_value": "intra.amr.kpmg.com\nintra.aspac.kpmg.com\nintra.ema.kpmg.com\nintra.qa.kpmg.com\nintra.stg.kpmg.com\npersonal2.kpmg.com\npersonal.dev.kpmg.com\npersonal.qa.kpmg.com\npersonal.stg.ema.kpmg.com\nplatforms.dev.kpmg.com\nplatforms.ema.kpmg.com\nplatforms.qa.kpmg.com\nplatforms.stg.ema.kpmg.com",
	// "id": 2383181286,
	// "entry_timestamp": "2020-01-27T14:44:25.937",
	// "not_before": "2017-09-08T00:00:00",
	// "not_after": "2018-04-12T23:59:59"
	Issuer_ca_id    uint
	Issuer_name     string
	Name_value      string
	Id              uint
	Entry_timestamp string
	Not_before      string
	Not_after       string
}
type ProcessingResult struct {
	Name          string
	CNAMEPointsTo []string
	Error         error
	ARecords      []string
}

func processname(name string) ProcessingResult {
	var res ProcessingResult
	res.Name = name

	cname, ok := lookupCNAME(name+".", DNSSERVER)
	//fmt.Println(cname, ok)
	if ok == false {
		s := fmt.Sprintf("Can't process CNAME lookup for %v\n", name)
		res.Error = errors.New(s)
		return res
		//panic(err)
	}
	if len(cname) > 0 {
		// it's a CNAME that points to something
		res.CNAMEPointsTo = cname
		a, ok := lookupA(name+".", DNSSERVER)
		if ok {
			res.ARecords = a
		} else {
			s := fmt.Sprintf("Can't process A lookup for %v\n", name)
			res.Error = errors.New(s)
			return res
		}
	}
	return res
}
func worker(in chan string, out chan ProcessingResult) {
	for name := range in {
		out <- processname(name)
	}
}
func main() {

	//url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", os.Args[1])
	//doc, err := http.Get(url)
	var body []byte
	body, err := ioutil.ReadFile("/tmp/a.json")

	if err != nil {
		fmt.Println(err)
		return
	}
	//var i int
	//body, err = ioutil.ReadAll(doc)
	//body, err = ioutil.ReadAll(doc.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	records := make([]CRTRecord, 0)
	err = json.Unmarshal(body, &records)
	if err != nil {
		fmt.Println(err)
		return
	}

	//fmt.Println(records)
	queue := make(chan string)
	results := make(chan ProcessingResult)
	recmap := make(map[string]bool)
	counter := 0
	for i := 0; i < 3; i++ {
		go worker(queue, results)
	}

	go func() {
		for res := range results {
			// cname, ok := lookupCNAME(s+".", "8.8.8.8:53")
			// //fmt.Println(cname, ok)
			// if ok == false {
			// 	fmt.Printf("Can't process %v\n", s)
			// 	//panic(err)
			// 	continue
			// }
			// if len(cname) > 0 {
			// 	a, ok := lookupA(s+".", "8.8.8.8:53")
			// 	if ok == false {
			// 		fmt.Printf("Can't process %v\n", s)
			// 		//panic(err)
			// 		continue
			// 	}
			if len(res.CNAMEPointsTo) > 0 {
				if len(res.ARecords) > 0 {
					fmt.Printf("%v: is a CNAME and points to %v and resolves to %v\n",
						res.Name,
						strings.Join(res.CNAMEPointsTo, ", "),
						strings.Join(res.ARecords, ", "),
					)
				} else {
					fmt.Printf("!!! %v: is a CNAME and points to %v and resolves to nothing (%v)\n",
						res.Name,
						strings.Join(res.CNAMEPointsTo, ", "),
						strings.Join(res.ARecords, ", "),
					)
				}

			}
		}
	}()

	fmt.Printf("Total %v records\n", len(records))
	for i := 0; i < len(records); i++ {
		nv := strings.Split(records[i].Name_value, " ")
		// fmt.Println(nv)
		for _, cert_values := range nv {
			for _, s := range strings.Split(cert_values, "\n") {
				if _, ok := recmap[s]; !ok {
					recmap[s] = true
					queue <- s
					counter += 1
				}

			}
		}
	}
	close(queue)
	fmt.Printf("Loaded %v results\n", counter)

}
