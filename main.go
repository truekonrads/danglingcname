package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	. "github.com/truekonrads/danglingcname/dnsdb"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
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
		log.Errorf("Unble to resolve: %s, %v", target, err)
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

	targetDomain := flag.String("domain", "", "Target domain.")
	dnsServer := flag.String("server", DNSSERVER, "DNS Server. (Optional)")
	numWorkers := flag.Int("workers", 5, "Number of workers (Optional)")
	useDNSDB := flag.Bool("dnsdb", false, "Use DNSDB (set DNSDB_KEY env var) (Optional)")
	usecrt := flag.Bool("usecrtsh", false, "Use crt.sh as source")
	sourcefile := flag.String("sourcefile", "", "Specify a source file to read DNS records, one per line (Optional)")
	debug := flag.Bool("debug", false, "Debug mode")
	// jsonFile := flag.String("jsonfile", "", "JSON file from which to read results (Optional)")
	flag.Parse()
	// if *targetDomain == "" {
	// 	flag.PrintDefaults()
	// 	os.Exit(1)
	// }
	if *debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debugging on")
	}
	targetMap := make(map[string]bool)
	DNSSERVER = *dnsServer

	var body []byte
	var err error
	var dnsdb_records []RRSetAnswer
	var records []CRTRecord
	var wg sync.WaitGroup
	var rwg sync.WaitGroup
	//log.Debug(fmt.Sprintf("Targeting %v\n", *targetDomain))
	//fmt.Println("useDNSDB: ", *useDNSDB)
	//fmt.Println("usecrt: ", *usecrt)

	if *useDNSDB {
		if *targetDomain == "" {
			fmt.Println("Please specify a domain!")
			flag.PrintDefaults()
			os.Exit(1)
		}
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
		for _, r := range dnsdb_records {
			var rrname string
			if strings.HasSuffix(r.RRName, ".") {
				rrname = r.RRName[:len(r.RRName)-1]
			} else {
				rrname = r.RRName
			}
			targetMap[rrname] = true

		}
		log.Debug(fmt.Sprintf("Total %v records received from dnsdb\n", len(dnsdb_records)))

	}

	if *usecrt {
		if *targetDomain == "" {
			log.Println("Please specify a domain!")
			flag.PrintDefaults()
			os.Exit(1)
		}
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
		for i := 0; i < len(records); i++ {
			nv := strings.Split(records[i].Name_value, " ")
			// fmt.Println(nv)
			for _, cert_values := range nv {
				for _, s := range strings.Split(cert_values, "\n") {
					targetMap[s] = true
				}
			}
		}
		log.Debug(fmt.Sprintf("Total %v records received from crt.sh\n", len(records)))
	}

	if len(*sourcefile) > 0 {

		var fh *os.File
		if fh, err = os.Open(*sourcefile); err != nil {
			log.Errorf("Can't read/open file '%s': %v", *sourcefile, err)
			return
		}
		i := 0
		scanner := bufio.NewScanner(fh)
		for scanner.Scan() {
			targetMap[scanner.Text()] = true
			i += 1
		}
		log.Debugf("Total %v records received from %s\n", i, *sourcefile)
	}

	//fmt.Println(records)
	queue := make(chan string)
	results := make(chan ProcessingResult)
	// recmap := make(map[string]bool)
	// counter := 0
	for i := 0; i < *numWorkers; i++ {

		go func() {
			wg.Add(1)
			worker(queue, results)
			wg.Done()
		}()
	}

	go func() {
		rwg.Add(1)
		defer rwg.Done()
		for res := range results {
			if len(res.CNAMEPointsTo) > 0 {
				if len(res.ARecords) > 0 {
					log.Debugf("%v: is a CNAME and points to %v and resolves to %v\n",
						res.Name,
						strings.Join(res.CNAMEPointsTo, ", "),
						strings.Join(res.ARecords, ", "),
					)
				} else {
					log.Infof("%v: is a CNAME and points to %v and resolves to nothing (%v)\n",
						res.Name,
						strings.Join(res.CNAMEPointsTo, ", "),
						strings.Join(res.ARecords, ", "),
					)
				}

			}
		}
	}()
	for key, _ := range targetMap {
		queue <- key
	}
	close(queue)
	wg.Wait()
	close(results)
	rwg.Wait()
}
