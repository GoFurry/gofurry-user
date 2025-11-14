package service

import (
	"math/rand"
	"strconv"
	"time"

	"github.com/GoFurry/gofurry-user/apps/oauth/dao"
	"github.com/GoFurry/gofurry-user/apps/oauth/models"
	"github.com/GoFurry/gofurry-user/apps/proto/githuboauth"
	ud "github.com/GoFurry/gofurry-user/apps/user/dao"
	um "github.com/GoFurry/gofurry-user/apps/user/models"
	us "github.com/GoFurry/gofurry-user/apps/user/service"
	"github.com/GoFurry/gofurry-user/common"
	"github.com/GoFurry/gofurry-user/common/log"
	cm "github.com/GoFurry/gofurry-user/common/models"
	cs "github.com/GoFurry/gofurry-user/common/service"
	"github.com/GoFurry/gofurry-user/common/util"
	"github.com/gofiber/fiber/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type oauthService struct{}

var oauthSingleton = new(oauthService)

func GetOauthService() *oauthService { return oauthSingleton }

func (s oauthService) GithubLogin(c *fiber.Ctx, code string) (string, common.GFError) {
	// 单体架构版本
	//accessCode, gfsErr := cs.GetGithubToken(code)
	//if gfsErr != nil || accessCode == "" {
	//	return "", common.NewServiceError("获取accessToken失败")
	//}
	//userInfo, gfsErr := cs.GetGithubUserInfo(accessCode)
	//if gfsErr != nil || userInfo == "" {
	//	return "", common.NewServiceError("请求用户信息失败")
	//}
	//userOpenID := gjson.Get(userInfo, "login").String() //github用户名唯一且不可修改

	// 微服务版本
	// 连接gRPC服务
	//creds, err := credentials.NewClientTLSFromFile("server.crt", "")
	//if err != nil {
	//	return "", common.NewServiceError("加载TLS证书失败: " + err.Error())
	//}
	conn, err := grpc.NewClient(
		"etcd:///github-oauth-service",
		grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		//grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return "", common.NewServiceError("连接gRPC服务失败: " + err.Error())
	}
	defer conn.Close()
	client := githuboauth.NewGithubOAuthServiceClient(conn)

	// gRPC 获取令牌
	tokenResp, err := client.GetAccessToken(c.Context(), &githuboauth.GetAccessTokenRequest{
		Code: code,
	})
	if err != nil {
		return "", common.NewServiceError("获取accessToken失败: " + err.Error())
	}
	if tokenResp.Error != "" {
		return "", common.NewServiceError("获取accessToken失败: " + tokenResp.Error)
	}
	accessToken := tokenResp.AccessToken

	// gRPC 获取用户信息
	userResp, err := client.GetUserInfo(c.Context(), &githuboauth.GetUserInfoRequest{
		AccessToken: accessToken,
	})
	if err != nil {
		return "", common.NewServiceError("获取userOpenID失败: " + err.Error())
	}
	if userResp.Error != "" {
		return "", common.NewServiceError("获取userOpenID失败: " + userResp.Error)
	}
	userInfo := userResp.UserInfo
	userOpenID := userInfo.Login // GitHub用户名 唯一标识

	return oauthLogin(c, userOpenID, "github")
}

// oauthLogin 注册/登录逻辑
func oauthLogin(c *fiber.Ctx, userOpenID string, provider string) (tokenStr string, err common.GFError) {
	//查找是否已注册
	oauthRecord, err := dao.GetOauthDao().FindOneByName(userOpenID, provider)
	if err != nil && err.GetMsg() != common.RETURN_RECORD_NOT_FOUND {
		return
	}
	//没找到就注册账户
	if err != nil && err.GetMsg() == common.RETURN_RECORD_NOT_FOUND {
		newUserRecord := &um.GfUser{
			Nickname: userOpenID,
			Email:    nil,
			Oauth:    true,
			Password: util.CreateMD5("123456" + common.COMMON_AUTH_SALT),
			Role:     "暂无",
			Status:   "normal",
			Avatar:   us.Avatars[rand.Intn(len(us.Avatars))],
		}
		newUserRecord.SetNewId()
		newUserRecord.SetName("UID:" + util.Int642String(newUserRecord.ID))
		newUserRecord.CreateTime = cm.LocalTime(time.Now())
		newUserRecord.UpdateTime = newUserRecord.CreateTime
		defaultInfo := "暂无个人简介."
		newUserRecord.Info = &defaultInfo

		newOauthRecord := &models.GfUserOauth{
			UserID:     newUserRecord.ID,
			Provider:   provider,
			OpenID:     userOpenID,
			CreateTime: cm.LocalTime(time.Now()),
		}
		newOauthRecord.SetNewId()
		// 记录入库
		err = ud.GetUserDao().Add(newUserRecord)
		if err != nil {
			return
		}

		err = dao.GetOauthDao().Add(newOauthRecord)
		if err != nil {
			return
		}
	}

	//登录账户
	oauthRecord, err = dao.GetOauthDao().FindOneByName(userOpenID, "github")
	if err != nil {
		return
	}

	var record *um.GfUser
	err = ud.GetUserDao().GetById(oauthRecord.UserID, &record)
	if err != nil {
		return
	}

	// 生成 token 存 redis
	tokenStr, tokenErr := util.NewToken(strconv.FormatInt(record.ID, 10), record.Name)
	if tokenErr != nil {
		log.Error(tokenErr)
		return "", common.NewServiceError("创建Token错误.")
	}
	cs.SetExpire("jwt:"+tokenStr, tokenStr, common.JWT_RELET_NUM*time.Hour) //存 token

	currentUser := um.CurrentUser{
		ID:   record.ID,
		Name: record.Name,
	}
	c.Locals(common.COMMON_AUTH_CURRENT, currentUser)

	return tokenStr, nil
}
