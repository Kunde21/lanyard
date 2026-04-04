package conformanceharness

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

func parseFormPostAutoSubmit(body string) (actionURL string, params url.Values, ok bool) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return "", nil, false
	}

	var form *html.Node
	var crawl func(*html.Node)
	crawl = func(n *html.Node) {
		if form != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "method") && strings.EqualFold(attr.Val, "post") {
					form = n
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			crawl(c)
		}
	}
	crawl(doc)
	if form == nil {
		return "", nil, false
	}

	actionURL = ""
	for _, attr := range form.Attr {
		if strings.EqualFold(attr.Key, "action") {
			actionURL = strings.TrimSpace(attr.Val)
		}
	}
	if actionURL == "" {
		return "", nil, false
	}

	params = url.Values{}
	var walkInputs func(*html.Node)
	walkInputs = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "name") {
					name = attr.Val
				}
				if strings.EqualFold(attr.Key, "value") {
					value = attr.Val
				}
			}
			if name != "" {
				params.Set(name, value)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkInputs(c)
		}
	}
	walkInputs(form)

	return actionURL, params, true
}

func isHTMLFormPostResponse(resp *http.Response) bool {
	ct := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "text/html") {
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	return true
}

func isFormPostAutoSubmitHTML(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "method=\"post\"") || strings.Contains(lower, "method='post'") || strings.Contains(lower, "method=post")
}
