package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/fox-one/mixin-sdk/utils"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type gatewayImp struct {
	serviceHost string
	gatewayHost string
}

// Token request token
type Token struct {
	memberID   string
	walletID   string
	merchantID string
	token      string
}

func (imp *gatewayImp) failServer(c *gin.Context, errs ...error) {
	resp := map[string]interface{}{
		"code": 2,
		"msg":  http.StatusText(http.StatusInternalServerError),
	}
	if len(errs) > 0 && errs[0] != nil {
		resp["hint"] = errs[0].Error()
	}
	c.AbortWithStatusJSON(http.StatusInternalServerError, resp)
}

func (imp *gatewayImp) request(ctx context.Context, method, url, body string, headers ...string) (int, []byte, error) {
	log.Debugln(url, method, body, headers)
	req, err := utils.NewRequest(url, method, body, headers...)
	if err != nil {
		log.Debugln("new request", err)
		return 0, nil, err
	}

	req = req.WithContext(ctx)
	resp, err := utils.DoRequest(req)
	if err != nil && (resp == nil || resp.Body == nil) {
		log.Debugln("do request", err)
		return 0, nil, err
	}
	data, err := utils.ReadResponse(resp)
	log.Debugln(string(data))
	return resp.StatusCode, data, err
}

func (imp *gatewayImp) extractBody(c *gin.Context) (body []byte, err error) {
	if cb, ok := c.Get(gin.BodyBytesKey); ok {
		if cbb, ok := cb.([]byte); ok {
			body = cbb
		}
	}

	if body == nil {
		body, err = ioutil.ReadAll(c.Request.Body)
		if err == nil {
			c.Set(gin.BodyBytesKey, body)
		}
	}

	return
}

func (imp *gatewayImp) authMember(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
			"code": 1103,
			"msg":  "member auth failed",
		})
		return ""
	}

	body, _ := imp.extractBody(c)
	params, err := json.Marshal(map[string]interface{}{
		"method": c.Request.Method,
		"uri":    c.Request.URL.String(),
		"body":   string(body),
		"token":  auth[7:],
	})
	if err != nil {
		imp.failServer(c, err)
		return ""
	}

	code, data, err := imp.request(c, "POST", imp.gatewayHost+"/member/validate", string(params))
	if err != nil {
		imp.failServer(c, err)
		return ""
	}

	var r = struct {
		MemberID string `json:"member_id,omitempty"`

		Code    int    `json:"code"`
		Message string `json:"msg,omitempty"`
		Hint    string `json:"hint,omitempty"`
	}{}

	if err := json.Unmarshal(data, &r); err != nil {
		imp.failServer(c, err)
		return ""
	}

	if r.Code > 0 {
		c.AbortWithStatusJSON(code, r)
		return ""
	}

	return r.MemberID
}

func (imp *gatewayImp) auth(c *gin.Context) *Token {
	memberID := imp.authMember(c)
	if c.IsAborted() {
		return nil
	}

	if len(memberID) == 0 {
		imp.failServer(c)
		return nil
	}

	code, data, err := imp.request(c, "GET", fmt.Sprintf("%s/dev/member/%s/auth", imp.gatewayHost, memberID), "")
	if err != nil {
		imp.failServer(c, err)
		return nil
	}

	var r = struct {
		WalletID   string `json:"wallet_id,omitempty"`
		MerchantID string `json:"merchant_id,omitempty"`
		Token      string `json:"token,omitempty"`

		Code    int    `json:"code"`
		Message string `json:"msg,omitempty"`
		Hint    string `json:"hint,omitempty"`
	}{}

	if err := json.Unmarshal(data, &r); err != nil {
		imp.failServer(c, err)
		return nil
	}

	if r.Code > 0 {
		c.AbortWithStatusJSON(code, r)
		return nil
	}

	return &Token{
		walletID:   r.WalletID,
		merchantID: r.MerchantID,
		token:      r.Token,
		memberID:   memberID,
	}
}

func (imp *gatewayImp) public(c *gin.Context) {
	service := c.Param("service")
	prefix := "/member/" + service + "/p"

	headers := []string{}

	if merchantID := c.GetHeader("Fox-Merchant-Id"); len(merchantID) > 0 {
		headers = append(headers, "Fox-Merchant-Id", merchantID)
	}

	method := c.Request.Method
	uri := c.Request.URL.String()
	body, _ := imp.extractBody(c)

	if strings.HasPrefix(uri, prefix) {
		uri = uri[len(prefix):]
	}
	if strings.HasSuffix(uri, "/gw") {
		uri = uri[:len(uri)-3]
	}

	code, data, err := imp.request(c, method, imp.serviceHost+uri, string(body), headers...)
	if err != nil {
		imp.failServer(c, err)
		return
	}

	c.Writer.Write(data)
	c.Writer.WriteHeader(code)
}

func (imp *gatewayImp) loginRequired(pinRequired bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		r := imp.auth(c)
		if c.IsAborted() {
			return
		}
		headers := []string{
			"Fox-Member-Id", r.memberID,
			"Fox-Merchant-Id", r.merchantID,
			"Fox-Wallet-Id", r.walletID,
			"Authorization", "Bearer " + r.token,
		}

		service := c.Param("service")
		prefix := "/member/" + service

		if pinRequired {
			prefix = "/pin"
		} else {
			prefix = "/u"
		}

		method := c.Request.Method
		uri := c.Request.URL.String()
		body, _ := imp.extractBody(c)

		if strings.HasPrefix(uri, prefix) {
			uri = uri[len(prefix):]
		}
		if strings.HasSuffix(uri, "/gw") {
			uri = uri[:len(uri)-3]
		}

		code, data, err := imp.request(c, method, imp.serviceHost+uri, string(body), headers...)
		if err != nil {
			imp.failServer(c, err)
			return
		}

		c.Writer.WriteHeader(code)
		c.Writer.Write(data)
	}
}

func (imp *gatewayImp) authAdmin(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
			"code": 1105,
			"msg":  "admin auth failed",
		})
		return ""
	}

	body, _ := imp.extractBody(c)
	params, err := json.Marshal(map[string]interface{}{
		"method": c.Request.Method,
		"uri":    c.Request.URL.String(),
		"body":   string(body),
		"token":  auth[7:],
	})
	if err != nil {
		imp.failServer(c, err)
		return ""
	}

	code, data, err := imp.request(c, "POST", imp.gatewayHost+"/admin/validate", string(params))
	if err != nil {
		imp.failServer(c, err)
		return ""
	}

	var r = struct {
		Admin *struct {
			MerchantID string `json:"merchant,omitempty"`
		} `json:"admin,omitempty"`

		Code    int    `json:"code"`
		Message string `json:"msg,omitempty"`
		Hint    string `json:"hint,omitempty"`
	}{}

	if err := json.Unmarshal(data, &r); err != nil {
		imp.failServer(c, err)
		return ""
	}

	if r.Code > 0 {
		c.AbortWithStatusJSON(code, r)
		return ""
	}

	return r.Admin.MerchantID
}

func (imp *gatewayImp) admin(c *gin.Context) {
	merchantID := imp.authAdmin(c)
	if c.IsAborted() {
		return
	}
	headers := []string{
		"Fox-Merchant-Id", merchantID,
	}

	service := c.Param("service")
	prefix := "/admin/" + service

	method := c.Request.Method
	uri := c.Request.URL.String()
	body, _ := imp.extractBody(c)

	if strings.HasPrefix(uri, prefix) {
		uri = uri[len(prefix):]
	}
	if strings.HasSuffix(uri, "/gw") {
		uri = uri[:len(uri)-3]
	}

	code, data, err := imp.request(c, method, imp.serviceHost+uri, string(body), headers...)
	if err != nil {
		imp.failServer(c, err)
		return
	}

	c.Writer.WriteHeader(code)
	c.Writer.Write(data)
}
