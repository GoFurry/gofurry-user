package controller

import (
	"github.com/GoFurry/gofurry-user/apps/oauth/service"
	"github.com/GoFurry/gofurry-user/common"
	"github.com/gofiber/fiber/v2"
)

type oauthApi struct{}

var OauthApi *oauthApi

func init() {
	OauthApi = &oauthApi{}
}

// @Summary Github 三方登录
// @Schemes
// @Description Github 三方登录
// @Tags Oauth
// @Accept json
// @Produce json
// @Param code query string true "code"
// @Success 200 {object} common.ResultData
// @Router /oauth/callback/github [Get]
func (api *oauthApi) GithubCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	token, err := service.GetOauthService().GithubLogin(c, code)
	if err != nil {
		return common.NewResponse(c).Error(err)
	}
	token = token
	return common.NewResponse(c).Success()
}
