package tkauth01

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/log"
)

var stiPaUrl string
var stiPaUsername string
var stiPaPassword string
var spc string

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

	fmt.Println(chlng)

	// Here we need to go get the service provider token for authentication
	accessToken, err := loginToSTIPA()

	if err != nil {
		fmt.Println("Login failed %v", err)
	} else {
		fmt.Println("Login successful")
	}
	fmt.Println("About to fetch SPC token")
	spcToken, err := fetchSPCToken(accessToken)
	fmt.Println("SPC token is", spc)
	fmt.Println("logging out of STI-PA")
	logOutofSTIPA(accessToken)

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
}

func GetSPC() string {
	return spc
}

// loginToSTIPA //logs in to the STI PA and returns the access token
func loginToSTIPA() (string, error) {
	//url := configurationInstance.URL
	client := &http.Client{}
	cURL := stiPaUrl + "/api/v1/auth/login"

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
		switch reflect.TypeOf(respMap["accessToken"]).Kind() {
		case reflect.String:
			accessToken := reflect.ValueOf(respMap["accessToken"]).String()
			return accessToken, nil
		default:
			return "", fmt.Errorf("error - PUT %v response status - %v; accessToken is not a string", stiPaUrl, resp.StatusCode)
		}
	default:
		return "", fmt.Errorf("error - %v", string(dataBuffer))
	}
}

func fetchSPCToken(accessToken string) (string, error) {
	client := &http.Client{}
	//cURL := url + "/api/v1/ca-list"
	cURL := stiPaUrl + "/api/v1/account/" + "980T" + "/token" // XXX This needs to be fixed
	verifyBody := map[string]interface{}{
		"atc": map[string]interface{}{
			"tktype":      "TNAuthList",
			"tkvalue":     spc,
			"ca":          false,
			"fingerprint": "SHA256 D3:AC:95:1E:7B:0A:01:42:A4:17:EB:AB:02:D7:99:EB:52:0A:F7:2C:F7:28:E3:22:0A:A2:58:4D:A0:31:5A:82",
		},
	}
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

	fmt.Println("Got the response")
	dataBuffer, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		fmt.Println("error - Cannot read json body err: %v\n", err)
		return "", err
	}
	contenType := resp.Header.Get("Content-Type")
	if !strings.Contains(contenType, "application/jose+json") {
		fmt.Println("content is not JSON object\n")
		return "", fmt.Errorf("error - GET %v response status - %v; content is not JSON object", stiPaUrl, resp.StatusCode)
	}

	respMap := make(map[string]interface{})
	err = json.Unmarshal(dataBuffer, &respMap)
	if err != nil {
		return "", fmt.Errorf("GET %v response status - %v; unable to parse JSON object in response body - %v", stiPaUrl, resp.StatusCode, err)
	}

	d1 := fmt.Sprintf("%s %s\n%s %s", "Returned status is:", resp.Status, "Returned message is: ", respMap["message"])

	err = ioutil.WriteFile("spc.log", []byte(d1), 0644)

	if err != nil {
		fmt.Println("Failed to create log file %v", err)
		return "", fmt.Errorf("Failed to create log file")
	}
	var jwt string
	//var crl string
	switch resp.StatusCode {
	case 200:
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
		break

	default:
		return "", fmt.Errorf("error - %v", string(dataBuffer))
	}

	fmt.Println("SPC token is ", jwt)
	//encodedResp, err := decodeJwt(jwt)

	//if err != nil {
	//	return err
	//}

	//caListRsp, err := base64Decode(encodedResp)
	//respMap = make(map[string]interface{})

	//if err := json.Unmarshal(caListRsp, &respMap); err != nil {
	///	return err
	//}

	// fmt.Println("EXP TIME is ", reflect.ValueOf(respMap["exp"]))

	//fmt.Println("CRL from token is", crl)
	//fmt.Println("Attempting to download CRL from STI-PA")
	//fetchStiPACrl(crl)

	return jwt, nil
}

func base64Decode(sig string) ([]byte, error) {
	// add back missing padding
	switch len(sig) % 4 {
	case 1:
		sig += "==="
	case 2:
		sig += "=="
	case 3:
		sig += "="
	}
	return base64.URLEncoding.DecodeString(sig)
}

type Verifier func(data []byte, signature []byte) (err error)

func verifyWithSigner(token string, ver Verifier) error {
	parts := strings.Split(token, ".")
	signedPart := []byte(strings.Join(parts[0:2], "."))
	signatureString, err := base64Decode(parts[2])
	if err != nil {
		return err
	}
	return ver(signedPart, signatureString)
}

func verifyEC(token string, key *ecdsa.PublicKey) error {
	ver := func(data []byte, signature []byte) (err error) {
		h := sha256.New()
		_, _ = h.Write(data)
		r := new(big.Int).SetBytes(signature[:len(signature)/2])
		s := new(big.Int).SetBytes(signature[len(signature)/2:])
		if ecdsa.Verify(key, h.Sum(nil), r, s) {
			return nil
		}
		return fmt.Errorf("Incorrect Signature")
	}
	return verifyWithSigner(token, ver)
}

func logOutofSTIPA(accessToken string) error {
	client := &http.Client{}
	cURL := stiPaUrl + "/api/v1/auth/logout"

	req, _ := http.NewRequest("POST", cURL, nil)
	req.Header.Set("accept", "application/jose+json")
	req.Header.Set("Authorization", accessToken)
	resp, err := client.Do(req)

	if err != nil {
		return fmt.Errorf("error - %v - POST%v failed", err, stiPaUrl)
	}

	contenType := resp.Header.Get("Content-Type")
	if !strings.Contains(contenType, "application/json") {
		fmt.Errorf("content is not JSON object\n")
		return fmt.Errorf("error - POST %v response status - %v; content is not JSON object", stiPaUrl, resp.StatusCode)
	}

	switch resp.StatusCode {
	case 200:
		fmt.Println("Logged out successfully\n")
		return nil
	default:
		return fmt.Errorf("Failed to logout")
	}
}
