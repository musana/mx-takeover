package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sync"

	"github.com/mailgun/mailgun-go/v3"

	"log"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gammazero/workerpool"
	tld "github.com/jpillora/go-tld"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

var (
	worker         *int
	help           *bool
	expr_day       *int
	mailgun_api    *string
	check_whois    *bool
	verbose        *bool
	only_mx        *bool
	output         *string
	mutex          sync.Mutex
	urls           []string
	mail_providers *[]string
	record_info    = make(map[string][]string)
)

func init() {
	mailgun_api = flag.String("mailgun-api", "", "mailgun api for mx domain takeover automaticly")
	check_whois = flag.Bool("check-whois", false, "Check whois for detecting unregistered mx domain or will be expire soon")
	expr_day = flag.Int("expire-day", 30, "Estimated days for expiration")
	only_mx = flag.Bool("show-only-mx", false, "show only that have mx records")
	verbose = flag.Bool("v", false, "Print all log")
	worker = flag.Int("w", 8, "number of worker")
	output = flag.String("output", "", "Save output to file as json")
	help = flag.Bool("h", false, "help")
}

func main() {
	printBanner()
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *verbose {
		printConf()
	}

	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe == 0 {
		color.Red("No data found in pipe. urls must given using pipe!")
		os.Exit(1)
	} else {
		readFromStdin()
	}

	color.Cyan("[*] Scan Starting Time: %s", time.Now().Format("2006-01-02 15:04:05"))

	if *mailgun_api == "" {
		color.Yellow("[!] Mailgun-api was not provided. You should register domain to mailgun manually")
	}

	if *check_whois == false {
		color.Yellow("[!] Check-whois argument was not provided. It will not checked whois lookup aganist MX domains that found.")
	}

	len_url := len(urls)
	color.Cyan("[*] %d domain will be scanned.", len_url)

	wp := workerpool.New(*worker)

	for id, r := range urls {
		r := r
		wp.Submit(func() {
			getDNSRecord(id, r, mail_providers)
		})
	}

	wp.StopWait()
	defer color.Cyan("[*] End Time: %s", time.Now().Format("2006-01-02 15:04:05"))

	if *output != "" {
		defer writeToFile(*output, record_info)
	}

	if *only_mx {
		defer scanSummary()
	}

	defer whoisMXDomain(record_info)
	if *check_whois {
		defer color.Cyan("[*] Domains that expire in less than %d days", *expr_day)
	}
}

func readFromStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		u := scanner.Text()
		if strings.HasPrefix(u, "https://") {
			url := strings.ReplaceAll(u, "https://", "")
			urls = append(urls, url)

		} else if strings.HasPrefix(u, "http://") {
			url := strings.ReplaceAll(u, "http://", "")
			urls = append(urls, url)
		} else {
			continue
		}
	}
}

func getDNSRecord(id int, domain string, mail_providers *[]string) {
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.0.0.1:53", "208.67.222.222:53"}
	retries := 2
	hostname := domain
	dnsClient := retryabledns.New(resolvers, retries)
	_, err := dnsClient.Resolve(hostname)
	if err != nil {
		color.Yellow("%s -> %s skipping...", err, hostname)
	}

	dnsResponses, err := dnsClient.Query(hostname, dns.TypeMX)
	if err != nil {
		color.Yellow("%s -> %s skipping...", err, hostname)
	}

	if *verbose {
		log.Println(domain, "MX", dnsResponses.MX)
	}

	if len(dnsResponses.MX) > 0 {
		if *only_mx {
			log.Println(domain, "MX", dnsResponses.MX)
		}
		if checkMXForMailgun(domain, dnsResponses.MX) {
			if *mailgun_api != "" {
				_, err := checkTakeover(domain, *mailgun_api)
				if err != nil {
					api_error := strings.ReplaceAll(err.Error(), "\n", "")
					if strings.Contains(api_error, "Error: ") {
						color.Red("[-] Mailgun API Response -> %s", strings.Split(api_error, "Error: ")[1])
					} else {
						color.Red("[-] ERROR:%s", api_error)
					}
				} else {
					color.Green("[+] Domain reclaimed successfully! :: %s\n", domain)
				}
			}
		} else {
			if *check_whois {
				parseMXDomain(domain, dnsResponses.MX)
			}
		}
	}
}

func checkMXForMailgun(domain string, mxs []string) bool {
	mailgun_mx := [2]string{"mxa.mailgun.org", "mxb.mailgun.org"}
	for _, s := range mxs {
		for _, m := range mailgun_mx {
			if s == m {
				color.Green("[+] Possible Takeover Found! :: %s MX %s", domain, m)
				return true
			}
		}
	}
	return false
}

func checkTakeover(domain, apiKey string) (mailgun.DomainResponse, error) {
	mg := mailgun.NewMailgun(domain, apiKey)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	return mg.CreateDomain(ctx, domain, &mailgun.CreateDomainOptions{
		SpamAction: mailgun.SpamActionTag,
		Wildcard:   false,
	})
}

// find mx domain. (sub.mail.google.com -> google.com)
func parseMXDomain(domain string, mxlist []string) {
	for _, mxd := range mxlist {
		// for parsing corretly added http:// schema.
		u, _ := tld.Parse("http://" + mxd)
		mx_domain := u.Domain + "." + u.TLD
		mutex.Lock()
		if !contains(record_info[mx_domain], domain) {
			record_info[mx_domain] = append(record_info[mx_domain], domain)
		}
		mutex.Unlock()
	}
}

func whoisMXDomain(domains map[string][]string) {
	for mx_domain, dmn := range domains {
		resp_whois, err := whois.Whois(mx_domain)
		if err == nil {
			if result, err := whoisparser.Parse(resp_whois); err == nil {
				if result.Domain.ExpirationDate != "" {
					expireMXDomain(mx_domain, result.Domain.ExpirationDate, dmn)
				}
			} else if err.Error() == "whoisparser: domain is not found" {
				color.Green("[+] Unregistered MX domain was detected! %s MX %s", dmn, mx_domain)
			} else {
				fmt.Println("Error Detected!", err)
			}
		}
	}
}

func contains(domains []string, domain string) bool {
	for _, d := range domains {
		if d == domain {
			return true
		}
	}
	return false
}

func expireMXDomain(mx_domain, expire_date string, dmn []string) {
	date := time.Now()
	format := "2006-01-02T15:04:05Z"
	then, _ := time.Parse(format, expire_date)
	diff := then.Sub(date)
	days_remain := int(diff.Hours() / 24)
	len_dmn := len(dmn)
	if days_remain < *expr_day {
		color.Green("[+] %s will be expired after [%d] days. It being used by %d diffirent domain. Expire Time: [%s]. Domains that used by this mx:", mx_domain, days_remain, len_dmn, expire_date) // number of days
		fmt.Println(dmn)
	}
}

func scanSummary() {
	for mx, domains := range record_info {
		fmt.Printf("%s being used %d different domains. %s mx record being used by these domains : %s \n", mx, len(domains), mx, domains)
	}
}

func writeToFile(filename string, data map[string][]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	map_to_json, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error: ", err.Error())
	} else {
		_, err = io.WriteString(file, string(map_to_json))
		if err != nil {
			return err
		}
	}
	color.Cyan("[*] Scan results was saved to %s", filename)
	return file.Sync()
}

func printConf() {
	fmt.Printf(`
_____________________________________________

Worker      	: %d
Max Expire Day	: %d
Check Whois  	: %t
Show Only MX  	: %t
Verbose      	: %t
Output File  	: %s
_____________________________________________

`, *worker, *expr_day, *check_whois, *only_mx, *verbose, *output)
}

func printBanner() {
	fmt.Println(`
                     _        _                                                                                                       
 _ __ ___ __  __    | |_ __ _| | _____  _____   _____ _ __ 
| '_ ' _ \\ \/ /____| __/ _' | |/ / _ \/ _ \ \ / / _ \ '__|
| | | | | |>  <_____| || (_| |   <  __/ (_) \ V /  __/ |   
|_| |_| |_/_/\_\     \__\__,_|_|\_\___|\___/ \_/ \___|_|   
														
hunting misconfigured MX records
musana.net | @musana
 `)
}
