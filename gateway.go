package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/fox-one/gin-contrib/gin_helper"
	"github.com/fox-one/httpclient"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type gatewayImp struct {
	gatewayHost string
	gateway     *httpclient.Client
	service     *httpclient.Client
}

// Token request token
type Token struct {
	memberID       string
	walletID       string
	merchantWallet string
	merchantID     string
	token          string
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

func (imp *gatewayImp) redirect(c *gin.Context, prefix string, headers ...string) {
	method := c.Request.Method
	uri := c.Request.URL.String()
	body, _ := imp.extractBody(c)

	if strings.HasPrefix(uri, prefix) {
		uri = uri[len(prefix):]
	}

	{
		// TODO remove
		if strings.HasSuffix(uri, "/gw") {
			uri = uri[:len(uri)-3]
		} else if idx := strings.Index(uri, "/gw?"); idx >= 0 {
			uri = uri[:idx] + uri[idx+3:]
		}
	}

	log.Debugln("do redirect", method, uri)

	req, err := http.NewRequest(method, uri, ioutil.NopCloser(bytes.NewReader(body)))
	if err != nil {
		gin_helper.FailServer(c, err)
		return
	}

	for i := 0; i < len(headers)-1; i += 2 {
		c.Request.Header.Set(headers[i], headers[i+1])
	}

	for k, v := range c.Request.Header {
		req.Header[k] = v
	}

	if err := imp.service.Redirect(c.Request.Context(), req, c.Writer); err != nil {
		gin_helper.FailServer(c, err)
		return
	}
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

	body, err := imp.extractBody(c)
	if err != nil {
		imp.failServer(c, err)
		return ""
	}

	resp := imp.gateway.POST("/member/validate").
		P("method", c.Request.Method).
		P("uri", c.Request.URL.String()).
		P("body", string(body)).
		P("token", auth[7:]).
		Do(c.Request.Context())

	if err := resp.Err(); err != nil {
		imp.failServer(c, err)
		return ""
	}

	data, err := resp.Bytes()
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
		code, _ := resp.Status()
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

	resp := imp.gateway.GET(fmt.Sprintf("/dev/member/%s/auth", memberID)).
		Do(c.Request.Context())

	if err := resp.Err(); err != nil {
		imp.failServer(c, err)
		return nil
	}

	data, err := resp.Bytes()
	if err != nil {
		imp.failServer(c, err)
		return nil
	}

	var r = struct {
		WalletID       string `json:"wallet_id,omitempty"`
		MerchantID     string `json:"merchant_id,omitempty"`
		MerchantWallet string `json:"merchant_wallet_id,omitempty"`
		Token          string `json:"token,omitempty"`

		Code    int    `json:"code"`
		Message string `json:"msg,omitempty"`
		Hint    string `json:"hint,omitempty"`
	}{}

	if err := json.Unmarshal(data, &r); err != nil {
		imp.failServer(c, err)
		return nil
	}

	if r.Code > 0 {
		code, _ := resp.Status()
		c.AbortWithStatusJSON(code, r)
		return nil
	}

	return &Token{
		walletID:       r.WalletID,
		merchantID:     r.MerchantID,
		merchantWallet: r.MerchantWallet,
		token:          r.Token,
		memberID:       memberID,
	}
}

func (imp *gatewayImp) public(c *gin.Context) {
	service := c.Param("service")
	imp.redirect(c, "/p/"+service)
}

// TODO deprecated
func (imp *gatewayImp) publicDeprecated(c *gin.Context) {
	service := c.Param("service")
	imp.redirect(c, "/member/"+service+"/p")
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
			"Fox-Merchant-Wallet-Id", r.merchantWallet,
			"Fox-Wallet-Id", r.walletID,
			"Authorization", "Bearer " + r.token,
		}

		service := c.Param("service")
		prefix := "/member/" + service

		if pinRequired {
			prefix = prefix + "/pin"
		} else {
			prefix = prefix + "/u"
		}

		imp.redirect(c, prefix, headers...)
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

	resp := imp.gateway.POST("/admin/validate").
		P("method", c.Request.Method).
		P("uri", c.Request.URL.String()).
		P("body", string(body)).
		P("token", auth[7:]).
		Do(c.Request.Context())

	if err := resp.Err(); err != nil {
		imp.failServer(c, err)
		return ""
	}

	data, err := resp.Bytes()
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
		code, _ := resp.Status()
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
	prefix := "/admin/" + service + "/u"

	imp.redirect(c, prefix, headers...)
}
