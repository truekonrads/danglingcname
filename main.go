package main

import (
	"encoding/json"
	"flag"
	"fmt"
	// "github.com/fatih/color"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	. "github.com/truekonrads/danglingcname/dnsdb"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

import "errors"

var DNSSERVER string = "8.8.8.8:53"

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
		fmt.Println(target, err)
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
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	cname, ok := lookupCNAME(name, DNSSERVER)
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
		a, ok := lookupA(name, DNSSERVER)
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

	targetDomain := flag.String("domain", "", "Target domain. (Required)")
	dnsServer := flag.String("server", DNSSERVER, "DNS Server. (Optional)")
	numWorkers := flag.Int("workers", 5, "Number of workers (Optional)")
	useDNSDB := flag.Bool("dnsdb", false, "Use DNSDB (set DNSDB_KEY env var) (Optional)")
	usecrt := flag.Bool("use", false, "Use crt.sh as source")
	// jsonFile := flag.String("jsonfile", "", "JSON file from which to read results (Optional)")
	flag.Parse()
	if *targetDomain == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	DNSSERVER = *dnsServer

	var body []byte
	var err error
	var dnsdb_records []RRSetAnswer
	var records []CRTRecord
	log.Debug(fmt.Sprintf("[+] Targeting %v\n", *targetDomain))
	if !*useDNSDB && !*usecrt {
		fmt.Printf("Select at least one source\n")
		return
	}
	if *useDNSDB {
		log.Debug(fmt.Sprintf("Loading data from DNSDB\n"))
		key := os.Getenv("DNSDB_KEY")
		if len(key) == 0 {
			fmt.Println("No DNSDB_KEY found")
			return
		}
		dnsc := DNSDBClient{ApiKey: key}

		dnsdb_records, err = dnsc.Lookup(fmt.Sprintf("*.%s", *targetDomain), "CNAME")
		if err != nil {
			fmt.Println("DNSDB", err)
			return
		}
		log.Info(fmt.Sprintf("Sucesfully fetched from DNSDB %s\n", *targetDomain))

	}

	// if _, err = os.Stat(*jsonFile); err == nil {
	// 	body, err = ioutil.ReadFile(*jsonFile)
	// 	fmt.Printf("Sucesfully read %s", *jsonFile)
	// }
	if *usecrt {
		url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", *targetDomain)
		log.Info(fmt.Sprintf("Sucesfully fetched from crt.sh %s\n", *targetDomain))
		var doc *http.Response
		if doc, err = http.Get(url); err != nil {
			fmt.Println(err)
			return
		}
		body, err = ioutil.ReadAll(doc.Body)
		records = make([]CRTRecord, 0)
		err = json.Unmarshal(body, &records)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	//fmt.Println(records)
	queue := make(chan string)
	results := make(chan ProcessingResult)
	recmap := make(map[string]bool)
	counter := 0
	for i := 0; i < *numWorkers; i++ {
		go worker(queue, results)
	}

	go func() {

		for res := range results {
			if len(res.CNAMEPointsTo) > 0 {
				if len(res.ARecords) > 0 {
					log.Debug(
						fmt.Sprintf("%v: is a CNAME and points to %v and resolves to %v\n",
							res.Name,
							strings.Join(res.CNAMEPointsTo, ", "),
							strings.Join(res.ARecords, ", "),
						))
				} else {
					log.Info(fmt.Sprintf("!!! %v: is a CNAME and points to %v and resolves to nothing (%v)\n",
						res.Name,
						strings.Join(res.CNAMEPointsTo, ", "),
						strings.Join(res.ARecords, ", "),
					))
				}

			}
		}
	}()

	log.Debug(fmt.Sprintf("Total %v records received from crt.sh\n", len(records)))
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
	log.Debug(fmt.Sprintf("Loaded %v results from crt.sh\n", counter))
	counter = 0
	log.Debug(fmt.Sprintf("Total %v records received from dnsdb\n", len(dnsdb_records)))
	if len(dnsdb_records) > 0 {
		for _, r := range dnsdb_records {
			var rrname string
			if strings.HasSuffix(r.RRName, ".") {
				rrname = r.RRName[:len(r.RRName)-1]
			} else {
				rrname = r.RRName
			}
			if _, ok := recmap[rrname]; !ok {
				recmap[rrname] = true
				queue <- rrname
				counter += 1
			}

		}
	}
	log.Debug(fmt.Sprintf("Loaded %v new results from DNSDB\n", counter))
	close(queue)

}
