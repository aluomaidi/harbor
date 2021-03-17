package angel

import (
	"encoding/base64"
	"encoding/json"
	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils"
	"github.com/goharbor/harbor/src/common/utils/log"
	"github.com/goharbor/harbor/src/core/auth"
	"github.com/goharbor/harbor/src/core/config"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Auth implements Authenticator interface to authenticate user against Angel.
type Auth struct {
	auth.DefaultAuthenticateHelper
}

type Resp struct {
	Code    int         `json:"code"`
	Success bool        `json:"success"`
	Data    []AngelUser `json:"data"`
}

type AngelUser struct {
	Id         int    `json:"id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Nickname   string `json:"nickname"`
	Department string `json:"department"`
}

// Authenticate calls dao to authenticate user.
func (d *Auth) Authenticate(m models.AuthModel) (*models.User, error) {
	cfg, err := config.GetSystemCfg()
	if err != nil {
		return nil, err
	}
	endpoint := utils.SafeCastString(cfg[common.AngelEndpoint])
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint = endpoint + "/"
	}
	// web login
	if m.Token != "" {
		resp, err := http.Get(endpoint + "passport/is_valid?token=" + m.Token + "&data=true")
		defer resp.Body.Close()
		if err != nil {
			return nil, err
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var result Resp
		err = json.Unmarshal(body, &result)
		if err != nil {
			return nil, err
		}
		if result.Success {
			user := &models.User{
				Username:     result.Data[0].Username,
				Email:        result.Data[0].Email,
				Realname:     result.Data[0].Nickname,
				Comment:      "",
				Deleted:      false,
				Rolename:     "普通用户",
				Role:         0,
				HasAdminRole: false,
				ResetUUID:    "",
				Salt:         "",
				CreationTime: time.Time{},
				UpdateTime:   time.Time{},
				GroupList:    nil,
			}
			return user, nil
		}
		// docker login
	} else if m.Principal != "" && m.Password != "" {
		passwd := "Jbchen6" + m.Password + "xjdaI"
		params := url.Values{}
		params.Add("username", m.Principal)
		params.Add("password", base64.URLEncoding.EncodeToString([]byte(passwd)))
		resp, err := http.PostForm(endpoint+"/passport/login.action", params)
		defer resp.Body.Close()
		if err != nil {
			return nil, err
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		log.Debugf("docker login resp: %s", string(body))
		var result map[string]interface{}
		err = json.Unmarshal(body, &result)
		if result["success"] == "true" || result["success"] == true {
			user := &models.User{
				Username:     m.Principal,
				Email:        "",
				Realname:     m.Principal,
				Comment:      "",
				Deleted:      false,
				Rolename:     "普通用户",
				Role:         0,
				HasAdminRole: false,
				ResetUUID:    "",
				Salt:         "",
				CreationTime: time.Time{},
				UpdateTime:   time.Time{},
				GroupList:    nil,
			}
			return user, nil
		}
	}
	return nil, auth.NewErrAuth("Invalid credentials")
}

func (l *Auth) OnBoardUser(u *models.User) error {
	log.Infof("on board user:%s", u.Username)
	if u.Email == "" {
		if strings.Contains(u.Username, "@") {
			u.Email = u.Username
		} else {
			u.Email = u.Username + "@iflytek.com"
		}
	}
	u.Password = "12345678AbC" // Password is not kept in local db
	u.Comment = "from angel."  // Source is from Angel
	log.Infof("on board user:%+v", u)
	return dao.OnBoardUser(u)
}

// SearchUser -- Search user in sso
func (l *Auth) SearchUser(username string) (*models.User, error) {
	var queryCondition = models.User{
		Username: username,
	}
	return dao.GetUser(queryCondition)
}

func (l *Auth) PostAuthenticate(user *models.User) error {
	dbUser, err := dao.GetUser(models.User{Username: user.Username})
	if err != nil {
		return err
	}
	if dbUser == nil {
		return l.OnBoardUser(user)
	}
	user.UserID = dbUser.UserID
	user.HasAdminRole = dbUser.HasAdminRole
	fillEmailRealName(user)
	if err2 := dao.ChangeUserProfile(*user, "Email", "Realname"); err2 != nil {
		log.Warningf("Failed to update user profile, user: %s, error: %v", user.Username, err2)
	}

	return nil
}

func fillEmailRealName(user *models.User) {
	if len(user.Realname) == 0 {
		user.Realname = user.Username
	}
	if len(user.Email) == 0 {
		// TODO: handle the case when user.Username itself is an email address.
		user.Email = user.Username + "@iflytek.com"
	}
}

func init() {
	auth.Register("angel_auth", &Auth{})
}
