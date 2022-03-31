package main

import (
  "github.com/tidwall/gjson"
  "bufio"
  "encoding/json"
  "fmt"
    "io/ioutil"
  "net/http"
  "os"
  "strings"
  "log"
  "bytes"
  "net/url"
)

func main() {

  if len(os.Args) <= 1 {
        fmt.Println("Usage:", os.Args[0], "domain.com")
        return
    }
    
  domain := os.Args[1]


//done
 d,_ := jldc(domain)
//done
 a,_ := hacktarget(domain)
//done
  c,_ := urlsc(domain)
//done
  g,_ := threatcrowd(domain)
//done
  f,_ := sonar(domain)
//done
  j,_ := certsh(domain)
//done
  e,_ := alien(domain)
//done
  b,_ := sublist3r(domain)
//done
  h,_ := threatminer(domain)
//done
  i,_ := wayback(domain)
//done
  k,_ := Buf(domain)
//done 
  l,_ := Spotter(domain)
//done
  

  x := []string{}
  x = append(d,c...)
  x = append(x,a...)
  x = append(x,b...)
  x = append(x,e...)
  x = append(x,f...)
  x = append(x,g...)
  x = append(x,i...)
  x = append(x,j...)
  x = append(x,h...)
  x = append(x,k...)
  x = append(x,l...)


remDup := rD(x)
  for i := 0; i < len(remDup); i++ {
    if strings.Contains(remDup[i], domain[:len(domain)-3]) {
      fmt.Println(remDup[i])
    } else {
      continue
    	} 
    }
}

func rD(intSlice []string) []string  {
    keys := make(map[string]bool)
    list := []string{}
    for _, entry := range intSlice {
      if _, value := keys[entry]; !value {
        keys[entry] = true
        list = append(list, entry)
      }
    }
    return list
  }



func wayback(domain string) ([]string, error) {

  fetchURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey", domain)

  var wrapper [][]string
  err := getdata(fetchURL, &wrapper)
  if err != nil {
    return []string{}, err
  }
  d := make([]string, 0)
  skip := true
  for _, item := range wrapper {
    if skip {
      skip = false
      continue
    }

    if len(item) < 3 {
      continue
    }

    u, err := url.Parse(item[2])
    if err != nil {
      continue
    }

    d = append(d, u.Hostname())
  }

  return d, nil
}

func threatminer(domain string) ([]string, error) {
  fetchURL := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
  response, err := http.Get(fetchURL)

    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }

    responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  var d []string
  rdata := string(responseData)
  result := gjson.Get(rdata, "results")

  
  for _, name := range result.Array() {
    d = append(d, name.String())
  }
  return d,err
}

func sublist3r(domain string)([]string, error){
  fetchURL := fmt.Sprintf("https://api.sublist3r.com/search.php?domain=%s", domain)
  response, err := http.Get(fetchURL)
    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }
  responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  data := strings.Split(string(responseData), ",")
  var d []string
  ln := len(data)
  for i := 0; i < ln; i++ {
    store := data[i]
      if i == 0{
        store = store[1:]
      }
      store = store[:len(store)-1]
      if i == ln-1 {
        store = store[:len(store)-1]
      }
      store = store[1:]
      d = append(d, store)
   }
   return d, err
}


func alien(domain string)([]string, error) {
  fetchURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
  response, err := http.Get(fetchURL)

    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }

    responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  var d []string
  rdata := string(responseData)
  result := gjson.Get(rdata, "passive_dns.#.hostname")
  for _, name := range result.Array() {
    d = append(d, name.String())
  }
  return d,err
}

func getdata(url string, get interface{}) error {
  response, err := http.Get(url)
  if err != nil {
    return err
  }
  defer response.Body.Close()
  dec := json.NewDecoder(response.Body)
  return dec.Decode(get)
}

func Buf(domain string) ([]string, error) {
  domains := make([]string, 0)

  fetchURL := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)

  get := struct {
    Data []string `json:"FDNS_A"`
  }{}
  
  err := getdata(fetchURL, &get)
  if err != nil {
    return domains, err
  }

  for _, r := range get.Data {
    sites := strings.SplitN(r, ",", 2)
    if len(sites) != 2 {
      continue
    }
    domains = append(domains, sites[1])
  }

  return domains, nil
}

func Spotter(domain string) ([]string, error) {
  out := make([]string, 0)
  fetchURL := fmt.Sprintf("https://certspotter.com/api/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
  get := []struct {
    DNSNames []string `json:"dns_names"`
  }{}
  err := getdata(fetchURL, &get)
  if err != nil {
    return out, err
  }
  for _, d := range get {
    out = append(out, d.DNSNames...)
  }

  return out, nil
}

func jldc(domain string)([]string, error){
  fetchURL := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
  response, err := http.Get(fetchURL)
    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }
  responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  
  if string(responseData) == `[]` {
    return nil,nil
  }
  var d []string
  data := strings.Split(string(responseData), ",")

  ln := len(data)
  for i := 0; i < ln; i++ {
    store := data[i]
      if i == 0{
        store = store[1:]
      }
      store = store[:len(store)-1]
      if i == ln-1 {
        store = store[:len(store)-1]
      }
      store = store[1:]
    
      d = append(d, store)
   }
   return d,err
}

func hacktarget(domain string) ([]string, error){
  fetchURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
  response, err := http.Get(fetchURL)
  d := make([]string, 0)
    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }
  responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  domains := bufio.NewScanner(bytes.NewReader(responseData))
  for domains.Scan() {
    parts := strings.SplitN(domains.Text(), ",", 2)
    if len(parts) != 2 {
      continue
    } 
    d = append(d, parts[0])
    
  }

  return d, err
}


func urlsc(domain string) ([]string, error) {
  fetchURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s", domain)
  response, err := http.Get(fetchURL)

    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }

    responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  var d []string
  rdata := string(responseData)
  result := gjson.Get(rdata, "results.#.page.domain")
  for _, name := range result.Array() {
    d = append(d, name.String())
  }
  return d,err
}

func threatcrowd(domain string) ([]string, error){
  fetchURL := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
  response, err := http.Get(fetchURL)

    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }

    responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  var d []string
  rdata := string(responseData)
  result := gjson.Get(rdata, "subdomains")
  for _, name := range result.Array() {
    d = append(d, name.String())
  }
  return d,err
}

func sonar(domain string) ([]string, error){
  fetchURL := fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", domain)
  response, err := http.Get(fetchURL)
    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }
  responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  data := strings.Split(string(responseData), ",")
  var d []string
  ln := len(data)
  for i := 0; i < ln; i++ {
    store := data[i]
      if i == 0{
        store = store[1:]
      }
      store = store[:len(store)-1]
      if i == ln-1 {
        store = store[:len(store)-1]
      }
      store = store[1:]
      d = append(d, store)
    }
    return d,err
}

func certsh(domain string) ([]string, error) {
  fetchURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
  response, err := http.Get(fetchURL)

    if err != nil {
        fmt.Print(err.Error())
        os.Exit(1)
    }

    responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal(err)
    }
  var d []string
  rdata := string(responseData)
  result := gjson.Get(rdata, "#.common_name")
  for _, name := range result.Array() {
    d = append(d, name.String())
  }
  return d,err
}
