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
	"golang.org/x/net/idna"
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
	IcannRule  bool
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

func New(args ...string) (*TLDExtract, error) {
	cacheFile := ""
	if len(args)>0{
		cacheFile = args[0]
	}
	
	newMap := make(map[string]*Trie)
	rootNode := &Trie{ExceptRule: false, IcannRule:false, ValidTld: false, matches: newMap}
	
	var br *bufio.Reader
	if cacheFile==""{
		br = bufio.NewReader(strings.NewReader(public_suffix))
	} else {
		fin, err := os.Open(cacheFile)
		if err != nil {
			fmt.Println("v0.1.5")
			fmt.Println("download cacheFile：")
			fmt.Println("https://publicsuffix.org/list/public_suffix_list.dat")
			return &TLDExtract{}, err
		}
		defer fin.Close()
		br = bufio.NewReader(fin)
	}

	hasSuffix := false
	icann := false
	for {
		line, err := readLine(br)
		if err == io.EOF {
			break
		}
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "BEGIN ICANN DOMAINS") {
			icann = true
			continue
		}
		if strings.Contains(line, "END ICANN DOMAINS") {
			icann = false
			continue
		}
		
		if line=="" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//"){
			continue
		}

		// 检查是否为!开头的后缀，此后缀将不被作为后缀，并添加右侧的为后缀来修正
		exceptionRule := line[0] == '!'
		if exceptionRule {
			line = line[1:]
			if line==""{
				continue
			}
		}
		
		addTldRule(rootNode, strings.Split(line, "."), exceptionRule, icann)
		hasSuffix = true
		
		punycodeTld, err := idna.ToASCII(line)
		if err==nil && punycodeTld!=line && punycodeTld!=""{
			addTldRule(rootNode, strings.Split(punycodeTld, "."), exceptionRule, icann)
		}
		
		originalDomain, err := idna.ToUnicode(line)
		if err==nil && originalDomain!=line && originalDomain!=""{
			addTldRule(rootNode, strings.Split(originalDomain, "."), exceptionRule, icann)
		}
	}
	
	if hasSuffix==false{
		return &TLDExtract{}, errors.New("输入文件没有定义任何后缀")
	}
	
	return &TLDExtract{rootNode: rootNode}, nil
}

func addTldRule(rootNode *Trie, labels []string, ex, ic bool) {
	numlabs := len(labels)
	t := rootNode
	for i := numlabs - 1; i >= 0; i-- {
		lab := labels[i]
		except := ex && i==0
		valid := !ex && i==0
		icann := ic && i==0
		m, found := t.matches[lab]
		if !found {
			newMap := make(map[string]*Trie)
			t.matches[lab] = &Trie{ExceptRule: except, IcannRule:icann, ValidTld: valid, matches: newMap}
			m = t.matches[lab]
		}else if found && i == 0 {
			// 添加这个可以解决域名必须先后顺序的问题，后面的后缀可以覆盖前面的
			t.matches[lab].ExceptRule = except
			t.matches[lab].IcannRule = icann
			t.matches[lab].ValidTld = valid
		}
		t = m
	}
}

func (extract *TLDExtract) Extract(s string, args ...bool) *DomainResult {
	includePrivate := true
	if len(args)>0{
		includePrivate = args[0]
	}

	u, err := url.Parse(s)
	if err!=nil{
		return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
	}
	
	website := strings.ToLower(u.Host)
	website = strings.Trim(website, ".")
	website = strings.Trim(website, ":")
	path := u.Path
	query := u.RawQuery

	subdomain := website
	if strings.Index(website, ":")>=0{
		h, p, err := net.SplitHostPort(website)
		if err!=nil || h=="" || p==""{
			return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
		}
		subdomain = h
	}

	if strings.Index(subdomain, ".")<=0{
		return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
	}
	if strings.HasPrefix(subdomain, ".") || strings.HasSuffix(subdomain, "."){
		return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
	}
	
	prefix, domain, suffix := "", "", ""
	
	if net.ParseIP(subdomain)!=nil{ // 是纯ip地址
		domain = subdomain
	}else{ // 是域名
		prefix, domain, suffix = extract.extract(subdomain, includePrivate)
	}
	
	if domain=="" || website=="" || strings.Index(domain, ".")<=0 || 
			strings.Index(website, ".")<=0{
		return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, "."){
		return &DomainResult{Prefix: "", Domain: "", Suffix: "", Website:"", Subdomain: "", Path: "", Query: ""}
	}
	
	return &DomainResult{Prefix: prefix, Domain: domain, Suffix: suffix, Website:website, Subdomain: subdomain, Path: path, Query: query}
}

func (extract *TLDExtract) extract(subdomain string, includePrivate bool)(string, string, string){
	prefix, domain, suffix := "", "", ""
	domain_head, tld := extract.extractTld(subdomain, includePrivate)
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

func (extract *TLDExtract) extractTld(subdomain string, includePrivate bool) (domain_head, tld string) {
	labels := strings.Split(subdomain, ".")
	tldIndex, validTld := extract.getTldIndex(labels, includePrivate)
	if validTld {
		domain_head = strings.Join(labels[:tldIndex], ".")
		tld = strings.Join(labels[tldIndex:], ".")
	}
	return domain_head, tld
}

func (extract *TLDExtract) getTldIndex(labels []string, includePrivate bool) (int, bool) {
	t := extract.rootNode
	longestValidTldIdx := -1
	longestValidTld := false
	
	length := len(labels)
	for i := length - 1; i >= 0; i-- {
		lab := labels[i]
		
		n, found := t.matches[lab]
		if found==false{
			n, found = t.matches["*"]
		}

		if found && !n.ExceptRule && n.ValidTld && (includePrivate || n.IcannRule){
			longestValidTldIdx = i
			longestValidTld = true
			t = n
		}else if found && n.ExceptRule && i+1<length && (includePrivate || n.IcannRule){
			longestValidTldIdx = i+1
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









