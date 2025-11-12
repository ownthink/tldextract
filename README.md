# tldextract


```
package main

import (
	"fmt"
	"github.com/ownthink/tldextract"
)

func main() {
	var extract, _ = tldextract.New()

	url := "https://www.domain.cn:8443/fasdfa"

	tld := extract.Extract(url)
	prefix := tld.Prefix
	domain := tld.Domain
	suffix := tld.Suffix
	website := tld.Website
	subdomain := tld.Subdomain
	path := tld.Path
	query := tld.Query
	
	fmt.Println("prefix:", prefix, "domain:", domain, "suffix:", suffix, "website:", website, "subdomain:", subdomain, "path:", path, "query:", query,)
}
```
