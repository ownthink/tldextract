package tldextract

import (
	"fmt"
	"strings"
	"errors"
	"io"
	"os"
	"net"
	"bufio"
	"net/url"
	_ "embed"
	// "golang.org/x/net/idna"
)

type DomainResult struct {
	Prefix  string
	Domain string
	Suffix string
	Website string
	Subdomain string
	Path string
	Query string
}

type TLDExtract struct {
	rootNode   *Trie
}

type Trie struct {
	ExceptRule bool
	ValidTld   bool
	matches    map[string]*Trie
}

func readLine(r *bufio.Reader) (string, error) {
	var buffer []byte
	bs, isprefix, err := r.ReadLine()
	buffer = append(buffer, bs...)

	for isprefix && err == nil {
		var bs []byte
		bs, isprefix, err = r.ReadLine()
		buffer = append(buffer, bs...)
	}

	return string(buffer), err
}

//go:embed data/public_suffix_list.dat
var public_suffix string

func New(cacheFiles ...string) (*TLDExtract, error) {
	newMap := make(map[string]*Trie)
	rootNode := &Trie{ExceptRule: false, ValidTld: false, matches: newMap}
	
	hasSuffix := false
	var br *bufio.Reader
	if len(cacheFiles) == 0 {
		br = bufio.NewReader(strings.NewReader(public_suffix))
	} else {
		fin, err := os.Open(cacheFiles[0])
		if err != nil {
			fmt.Println("v0.0.1")
			fmt.Println("download cacheFile：")
			fmt.Println("https://publicsuffix.org/list/public_suffix_list.dat")
			return &TLDExtract{}, err
		}
		defer fin.Close()
		br = bufio.NewReader(fin)
	}

	for {
		line, err := readLine(br)
		if err == io.EOF {
			break
		}
		line = strings.TrimSpace(line)
		if line=="" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//"){
			continue
		}

		// 检查是否为!开头的后缀，此后缀将不被作为后缀
		exceptionRule := line[0] == '!'
		if exceptionRule {
			line = line[1:]
		}
		addTldRule(rootNode, strings.Split(line, "."), exceptionRule)
		hasSuffix = true
	}
	
	if hasSuffix==false{
		return &TLDExtract{}, errors.New("输入文件没有定义任何后缀")
	}
	
	return &TLDExtract{rootNode: rootNode}, nil
}

func addTldRule(rootNode *Trie, labels []string, ex bool) {
	numlabs := len(labels)
	t := rootNode
	for i := numlabs - 1; i >= 0; i-- {
		lab := labels[i]
		except := ex && i == 0
		valid := !ex && i == 0
		m, found := t.matches[lab]
		if !found {
			newMap := make(map[string]*Trie)
			t.matches[lab] = &Trie{ExceptRule: except, ValidTld: valid, matches: newMap}
			m = t.matches[lab]
		}else if found && i == 0 {
			// 添加这个可以解决域名必须先后顺序的问题，后面的后缀可以覆盖前面的
			t.matches[lab].ExceptRule = except
			t.matches[lab].ValidTld = valid
		}
		t = m
	}
}

func (extract *TLDExtract) Extract(s string) *DomainResult {
	u, err := url.Parse(s)
	if err!=nil{
		return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
	}
	
	website := strings.ToLower(u.Host)
	website = strings.Trim(website, ".")
	path := u.Path
	query := u.RawQuery

	subdomain := website
	h, _, err := net.SplitHostPort(website)
	if err==nil{ // 没有端口的将返回错误
		subdomain = h
	}
	
	prefix, domain, suffix := "", "", ""
	
	if net.ParseIP(subdomain)!=nil{ // 是纯ip地址
		domain = subdomain
	}else{ // 是域名
		prefix, domain, suffix = extract.extract(subdomain)
		
		// domain, err = idna.ToASCII(domain)
	}
	
	if domain=="" || website=="" || 
			strings.Index(domain, ".")<0 || strings.Index(website, ".")<0{
		return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
	}
	
	return &DomainResult{Prefix: prefix, Domain: domain, Suffix: suffix, Website:website, Subdomain: subdomain, Path: path, Query: query}
}

func (extract *TLDExtract) extract(url string)(string, string, string){
	prefix, domain, suffix := "", "", ""
	domain_head, tld := extract.extractTld(url)
	if domain_head=="" || tld==""{
		return prefix, domain, suffix
	}

	root := ""
	ps := strings.Split(domain_head, ".")
	length := len(ps)
	if length==1 {
		root = domain_head
	}else{
		prefix = strings.Join(ps[0:length-1], ".")
		root = ps[length-1]
	}

	if tld!="" && root!=""{ // 正常不用判断，保险起见还是判断下好
		suffix = "." + tld
		domain = root + "." + tld
	}

	return prefix, domain, suffix
}

func (extract *TLDExtract) extractTld(subdomain string) (domain_head, tld string) {
	labels := strings.Split(subdomain, ".")
	tldIndex, validTld := extract.getTldIndex(labels)
	if validTld {
		domain_head = strings.Join(labels[:tldIndex], ".")
		tld = strings.Join(labels[tldIndex:], ".")
	}
	return domain_head, tld
}

func (extract *TLDExtract) getTldIndex(labels []string) (int, bool) {
	t := extract.rootNode
	longestValidTldIdx := -1
	longestValidTld := false
	for i := len(labels) - 1; i >= 0; i-- {
		lab := labels[i]
		
		n, found := t.matches[lab]
		if found==false{
			n, found = t.matches["*"]
		}

		if found && !n.ExceptRule && n.ValidTld{
			longestValidTldIdx = i
			longestValidTld = true
			t = n
		}else if found{
			t = n
		}else{
			break
		}
	}
	
	return longestValidTldIdx, longestValidTld
}

func main() {
	// tldextract 库没更新

	url := "d2sm1dt3qpze3g.cloudfront.net"
	
	// url = "www.baidu.net"
	
	// url = "ec2-54-XXX-XXX-158.us-west-2.compute.amazonaws.com"

	url = "foo.*.uk"
	url = "foo.co.uk"
	url = "foo.bar.com"
	url = "allestörungen.at"
	
	// url = "www.amazonaws.com" //  bug
	
	// url = "baidu.cn"
	// url = "com.cn"
	
	// url = "aaa.sfafsda.kawasaki.jp"
	// url = "fsafda.kawasaki.jp" // 返回空
	// url = "afa.aaa.kawasaki.jp"
	// url = "aaa.kawasaki.jp"
	// url = "city.kawasaki.jp" // 返回空，因为没有kawasaki.jp后缀
	
	// url = "http://fasdfa.baidu.com"

	url = "sfa.blogspot.com"
	url = "www.kafe.co.il"
	url = "blogspot.co.il"
	
	url = "https://www.domain.cn:8443/fasdfa"
	
	// extract, _ := New("data/public_suffix_list.dat")
	
	extract, _ := New()
	
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

