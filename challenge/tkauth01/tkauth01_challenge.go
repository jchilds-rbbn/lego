package tkauth01

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/log"
	"github.com/square/go-jose"
)

var stiPaUrl string
var stiPaUsername string
var stiPaPassword string
var spc string
var tnAuthList string
var fingerPrint string

type ValidateFunc func(core *api.Core, domain string, chlng acme.Challenge) error

type Challenge struct {
	core     *api.Core
	validate ValidateFunc
	provider challenge.Provider
}

func NewChallenge(core *api.Core, validate ValidateFunc) *Challenge {
	return &Challenge{
		core:     core,
		validate: validate,
		// provider: provider,
	}
}

func (c *Challenge) SetProvider(provider challenge.Provider) {
	c.provider = provider
}

// Solve manages the provider to validate and solve the challenge.
func (c *Challenge) Solve(authz acme.Authorization) error {
	TnAuthList := authz.Identifier.Value
	log.Infof("[%s] acme: Trying to solve TKAUTH-01", TnAuthList)

	chlng, err := challenge.FindChallenge(challenge.TKAUTH01, authz)
	if err != nil {
		return err
	}

	// Here we need to go get the service provider token for authentication
	accessToken, err := loginToSTIPA()
	if err != nil {
		log.Infof("Could not log into STI-PA err %v", err)
		return err
	}
	spcToken, err := fetchSPCToken(accessToken)
	if err != nil {
		log.Infof("Could not log fetch SPC token err %v", err)
		return err
	}

	log.Infof("Retrieved SPC token")

	// logOutofSTIPA(accessToken)

	return c.validate(c.core, spcToken, chlng)
}

func SetStiPaUrl(url string) {
	stiPaUrl = url
}

func SetStiPaUser(name string) {
	stiPaUsername = name
}

func SetStiPaPassword(pw string) {
	stiPaPassword = pw
}

func SetSPC(code string) {
	spc = code

	// Convert to TnAuthList format for future use
	tnAuthList = spcToTnAuth(spc)
}

func GetSPC() string {
	return spc
}

func GetTNAuthList() string {
	return tnAuthList
}

func SetTNAuthList(tnAuth string) {
	tnAuthList = tnAuth
}

func SetFingerprint(fp string) {
	fingerPrint = "SHA256 " + fp
}

// loginToSTIPA //logs in to the STI PA and returns the access token
func loginToSTIPA() (string, error) {
	//url := configurationInstance.URL
	client := &http.Client{}
	cURL := stiPaUrl + "/api/v1/auth/login"

	log.Infof("Attempting to log into STI-PA")

	body := make(map[string]interface{})
	body["userId"] = stiPaUsername
	body["password"] = stiPaPassword
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(body)
	if err != nil {
		return "", fmt.Errorf("error - %v - Failed to format http body", err)
	}

	req, err := http.NewRequest("POST", cURL, buf)
	if err != nil {
		return "", fmt.Errorf("error - %v - http.NewRequest failed", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error - %v - PUT %v failed", err, stiPaUrl)
	}

	dataBuffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("error - Cannot read json body err: %v\n", err)
		return "", err
	}
	// contenType := resp.Header.Get("Content-Type")
	// if !strings.Contains(contenType, "application/json") {
	// 	fmt.Errorf("content is not JSON object\n")
	//	return "", fmt.Errorf("error - GET %v response status - %v; content is not JSON object", url, resp.StatusCode)
	//}

	respMap := make(map[string]interface{})
	err = json.Unmarshal(dataBuffer, &respMap)
	if err != nil {
		return "", fmt.Errorf("GET %v response status - %v; unable to parse JSON object in response body - %v", stiPaUrl, resp.StatusCode, err)
	}

	switch resp.StatusCode {
	case 200:
		if reflect.ValueOf(respMap["accessToken"]).IsValid() {
			switch reflect.TypeOf(respMap["accessToken"]).Kind() {
			case reflect.String:
				accessToken := reflect.ValueOf(respMap["accessToken"]).String()
				return accessToken, nil
			default:
				return "", fmt.Errorf("error - PUT %v response status - %v; accessToken is not a string", stiPaUrl, resp.StatusCode)
			}
		}
		return "", fmt.Errorf("error - %v", string(dataBuffer))
	default:
		return "", fmt.Errorf("error - %v", string(dataBuffer))
	}
}

func fetchSPCToken(accessToken string) (string, error) {
	client := &http.Client{}
	//cURL := url + "/api/v1/ca-list"
	cURL := stiPaUrl + "/api/v1/account/" + spc + "/token"
	verifyBody := map[string]interface{}{
		"atc": map[string]interface{}{
			"tktype":      "TNAuthList",
			"tkvalue":     tnAuthList,
			"ca":          false,
			"fingerprint": fingerPrint,
		},
	}

	log.Infof("Attempting to fetch SPC Token")

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(verifyBody)

	/*req, _ := http.NewRequest("GET", cURL, nil)
	req.Header.Set("accept", "application/json")
	req.Header.Set("Authorization", accessToken)*/

	req, _ := http.NewRequest("POST", cURL, buf)
	req.Header.Set("accept", "application/jose+json")
	req.Header.Set("Authorization", accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return "", fmt.Errorf("error - %v - GET %v failed", err, stiPaUrl)
	}

	dataBuffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Infof("Could not read response body err %v", err)
		return "", err
	}
	contenType := resp.Header.Get("Content-Type")
	if !strings.Contains(contenType, "application/jose+json") {
		log.Infof("Could not read response body err %v", err)
		return "", fmt.Errorf("error - GET %v response status - %v; content is not JSON object", stiPaUrl, resp.StatusCode)
	}

	respMap := make(map[string]interface{})
	err = json.Unmarshal(dataBuffer, &respMap)
	if err != nil {
		return "", fmt.Errorf("GET %v response status - %v; unable to parse JSON object in response body - %v", stiPaUrl, resp.StatusCode, err)
	}
	var jwt string
	//var crl string
	switch resp.StatusCode {
	case 200:
		if reflect.ValueOf(respMap["token"]).IsValid() {
			switch reflect.TypeOf(respMap["token"]).Kind() {
			case reflect.String:
				jwt = reflect.ValueOf(respMap["token"]).String()
				break
			default:
				return "", fmt.Errorf("error - PUT %v response status - %v; accessToken is not a string", stiPaUrl, resp.StatusCode)
			}
			switch reflect.TypeOf(respMap["crl"]).Kind() {
			case reflect.String:
				//crl = reflect.ValueOf(respMap["crl"]).String()
				break
			default:
				return "", fmt.Errorf("error - PUT %v response status - %v; crl is not a string", stiPaUrl, resp.StatusCode)
			}
		} else {
			return "", fmt.Errorf("error - %v", string(dataBuffer))
		}
		break

	default:
		return "", fmt.Errorf("error - %v", string(dataBuffer))
	}

	return jwt, nil
}

func logOutofSTIPA(accessToken string) error {
	client := &http.Client{}
	cURL := stiPaUrl + "/api/v1/auth/logout"

	log.Infof("Attempting to log out of STI-PA")

	req, _ := http.NewRequest("POST", cURL, nil)
	req.Header.Set("accept", "application/jose+json")
	req.Header.Set("Authorization", accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error - %v - POST%v failed", err, stiPaUrl)
	}

	contenType := resp.Header.Get("Content-Type")
	if !strings.Contains(contenType, "application/json") {
		log.Infof("Content is not json object")
		return fmt.Errorf("error - POST %v response status - %v; content is not JSON object", stiPaUrl, resp.StatusCode)
	}

	switch resp.StatusCode {
	case 200:
		return nil
	default:
		return fmt.Errorf("Failed to logout")
	}
}

type TnAuthList struct {
	SPC string `asn1:"explicit,tag:0,ia5"`
}

func spcToTnAuth(spc string) string {
	tnauthlist := make([]TnAuthList, 1)

	tnauthlist[0].SPC = spc
	mdata, err := asn1.Marshal(tnauthlist[0])
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(mdata)
}

func SetFingerprintFromPrivateKey(privateKey crypto.PrivateKey) error {

	fmt.Printf("SetFingerprintFromPrivateKey: setting fingerprint\n")

	var publicKey crypto.PublicKey
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		publicKey = k.Public()
	case *rsa.PrivateKey:
		publicKey = k.Public()
	}

	jwk := jose.JSONWebKey{Key: publicKey}
	fpBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}

	fingerPrint := fmt.Sprintf("%x", fpBytes)
	// after every two characters insert a colon(:)
	for index := 2; index < len(fingerPrint); index += 3 {
		fingerPrint = fingerPrint[:index] + ":" + fingerPrint[index:]
	}

	fmt.Printf("fingerprint = %v\n", fingerPrint)

	SetFingerprint(fingerPrint)

	return nil
}
