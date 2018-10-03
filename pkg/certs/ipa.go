// The None Provider
package certs

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var validStatusCodes = []int{200, 300}

type IPAProvider struct {
	Url      string
	Bits     int
	Ca_trust bool
	User     string
	Password string
	Realm    string
	attrs    map[string]string
	client   *http.Client
}

type IPAResult struct {
	Result  string   `json:"result"`
	Version string   `json:"version"`
	Error   IPAError `json:"error"`
}

type IPAError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Data    string `json:"data"`
	Name    string `json:"name"`
}

func (e IPAError) Error() string {
	return e.Message
}

func NewIPAProvider(url string, bits int, ca_trust bool, user string, password string, realm string, attrs map[string]string) *IPAProvider {
	p := &IPAProvider{
		Url:      url,
		Bits:     bits,
		Ca_trust: ca_trust,
		User:     user,
		Password: password,
		Realm:    realm,
		attrs:    attrs,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	p.client = client

	return p
}

func (p *IPAProvider) Provision(host string, validFrom string, validFor time.Duration, isCA bool, rsaBits int, ecdsaCurve string) (keypair KeyPair, certError error) {
	var err error
	var cookies []*http.Cookie

	// log in to freeIPA
	cookies, err = p.getLogin()
	if err != nil {
		return KeyPair{}, NewCertError("IPA login failed: \n\t" + err.Error())
	}

	// create new host
	hostData := fmt.Sprintf(`{"id": "0", "method": "host_add", "params": [["%s"],{"force": "true"}]}`, host)
	jsonHost := []byte(hostData)
	var resp *http.Response
	resp, err = p.apiCall(jsonHost, cookies)
	if err != nil {
		fmt.Errorf("Error creating host: %s", err.Error())
		return KeyPair{}, err
	}

	if !validResponse(resp.StatusCode) {
		fmt.Errorf("Response Code: %v", resp.Status)
		return KeyPair{}, NewErrBadHost("Got bad response code while creating host: \n\t" + resp.Status)
	}

	if success, result := successfulRequest(resp); !success {
		return KeyPair{}, result.Error
	}

	// create cert
	csr, csrErr := createCSR(host, p.attrs)
	if csrErr != nil {
		return KeyPair{}, err
	}

	csrData := fmt.Sprintf(`{
      "method": "cert_request",
      "params": [
        [ "%s" ],
        {
          "principal": "host/%s@%s",
          "request_type": "pkcs10",
          "add": "False"
        }
      ],
      "id":0
    }`,
		strings.Replace(string(csr), "\n", "\\n", -1),
		host,
		p.Realm)

	resp, err = p.apiCall([]byte(csrData), cookies)
	if err != nil {
		return KeyPair{}, NewCertError("Error creating certificate: \n\t" + err.Error())
	}

	fmt.Println(resp)
	if !validResponse(resp.StatusCode) {
		fmt.Errorf("Response Code: %v", resp.Status)
		return KeyPair{}, NewCertError("Invalid response code while creating IPA certificate: \n\n" + resp.Status)
	}

	if success, result := successfulRequest(resp); !success {
		return KeyPair{}, NewCertError("Failed creating new cert: \n\t" + result.Result)
	}

	return KeyPair{
		Cert:   []byte{},
		Key:    []byte{},
		Expiry: time.Now(),
	}, nil
}

func (p *IPAProvider) Deprovision(host string) error {
	return nil
}

func (p *IPAProvider) getLogin() ([]*http.Cookie, error) {
	data := url.Values{}
	data.Set("user", p.User)
	data.Add("password", p.Password)

	req, err := http.NewRequest("POST", p.Url+"/session/login_password", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fmt.Printf("request: %s %s : %s\n", req.Method, req.URL, req.Body)

	resp, err := p.client.Do(req)
	if err != nil {
		return []*http.Cookie{}, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("response Body: %s\n", string(body))
	for ck, cv := range resp.Cookies() {
		fmt.Printf("Got cookie %v: %s\n", ck, cv.String())
	}
	return resp.Cookies(), nil
}

func (p *IPAProvider) apiCall(data []byte, cookies []*http.Cookie) (*http.Response, error) {
	req, err := http.NewRequest("POST", p.Url+"/session/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Errorf("Error building host_add request: %s", err.Error())
		return &http.Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", p.Url)
	fmt.Printf("request: %s %s : %s\n", req.Method, req.URL, req.Body)
	for k, v := range req.Header {
		fmt.Printf("Header field %q, Value %q\n", k, v)
	}
	for _, cv := range cookies {
		req.AddCookie(cv)
	}

	return p.client.Do(req)

}

func validResponse(s int) bool {
	for _, a := range validStatusCodes {
		if a == s {
			return true
		}
	}
	return false
}

func successfulRequest(resp *http.Response) (bool, *IPAResult) {
	body, _ := ioutil.ReadAll(resp.Body)
	var result *IPAResult
	json.Unmarshal(body, &result)
	fmt.Println(body)
	if result.Error != (IPAError{}) {
		if !strings.Contains(result.Error.Error(), "already exists") {
			return false, result
		}
	}
	return true, result
}
