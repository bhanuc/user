package user

import (
	"github.com/gomango/utility"
	"github.com/gorilla/sessions"
	"labix.org/v2/mgo/bson"
	"net/http"
	"strings"
)

type FlashMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {

	tu := struct {
		Name     string `json:"name"`
		Lastname string `json:"lastname"`
		Email    string `json:"email"`
		Email2   string `json:"email2"`
	}{}
	utility.ReadJson(r, &tu)

	tu.Name = strings.Trim(tu.Name, " ")
	tu.Lastname = strings.Trim(tu.Lastname, " ")
	tu.Email = strings.Trim(tu.Email, " ")
	tu.Email2 = strings.Trim(tu.Email2, " ")

	e := make(map[string]FlashMessage)

	if tu.Name == "" {
		e["name"] = FlashMessage{"danger", "Please fill out your name"}
	}

	if tu.Lastname == "" {
		e["lastname"] = FlashMessage{"danger", "Please fill out your last name"}
	}

	if tu.Email == "" {
		e["email"] = FlashMessage{"danger", "Please enter a valid email-address"}
	}

	if tu.Email != tu.Email2 {
		e["email2"] = FlashMessage{"danger", "The two email addresses don't match"}
	}

	//userrepo.Collection.Find(bson.M{"email": tu.Email}).One(&foundmail)
	c, _ := UserR.Collection.Find(bson.M{"email": tu.Email}).Count()

	if c > 0 {
		e["general"] = FlashMessage{"danger", "The user with this email address already exists. If you pressed the [Sign up] button multiple times please check your mailbox " + tu.Email + "."}
	}

	data := make(map[string]interface{})

	if len(e) == 0 {
		user := new(User)
		user.Add(tu.Name, tu.Lastname, tu.Email)
		data["success"] = true
		e["success"] = FlashMessage{"success", "Your registration was successful. An email with your password has been sent to " + tu.Email + "."}
		data["flashes"] = e
		data["user"] = tu
	} else {
		data["flashes"] = e
		data["user"] = tu
	}
	utility.WriteJson(w, data)
}

func AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	// get email + password
	valid := false
	data := make(map[string]interface{})
	tc := struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		Rememberme bool   `json:"rememberme"`
	}{}
	tu := struct {
		Name string `json:"name"`
	}{}
	flashes := make(map[string]FlashMessage)

	utility.ReadJson(r, &tc)

	tc.Email = strings.Trim(tc.Email, " ")
	user, err := UserR.FindOneByEmail(tc.Email)
	// if user not found
	if err != nil {
		valid = false
	} else {
		// check if login allowed
		if user.LoginAllowed() {
			if valid = user.VerifyCredentials(tc.Email, tc.Password); valid == false {
				user.FailLogin()
			}
		} else {
			// login not allowed
			flashes["not_allowed"] = FlashMessage{"warning", "You have failed 3 login attempts in the last 15 Minutes. Please wait 15 Minutes from now on and try again."}
		}
	}

	data["valid"] = valid

	if valid {
		tu.Name = user.UserProfile.Name
		data["user"] = tu
		data["redirect"] = "/user/profile"
		user.Login(r.UserAgent(), r.RemoteAddr)
		session, _ := sessionStore.Get(r, "p")
		session.Values["user"] = user.Id.Hex()
		if tc.Rememberme {
			session.Options = &sessions.Options{
				Path:   "/",
				MaxAge: 86400 * 30 * 12,
			}
		}
		session.Save(r, w)
	} else {
		flashes["invalid"] = FlashMessage{"danger", "Login not successful. Either a user with this email address doesn't exist or the email and password combination is wrong"}
		data["flashes"] = flashes
	}

	utility.WriteJson(w, data)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	flashes := make(map[string]FlashMessage)
	session, _ := sessionStore.Get(r, "p")
	session.Values["user"] = nil
	session.Options = &sessions.Options{
		Path:   "/",
		MaxAge: -1,
	}
	session.Save(r, w)
	flashes["success"] = FlashMessage{"success", "You have been logged out"}
	data["flashes"] = flashes
	utility.WriteJson(w, data)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "p")
	data := make(map[string]interface{})
	flashes := make(map[string]FlashMessage)
	id, ok := session.Values["user"].(string)
	if ok {
		u, _ := UserR.FindOneByIdHex(id)
		data["profile"] = u.UserProfile
	} else {
		flashes["no_session"] = FlashMessage{"danger", "You are not logged in"}
		data["flashes"] = flashes
		data["redirect"] = "/user/login"
	}
	utility.WriteJson(w, data)
}

func UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "p")
	data := make(map[string]interface{})
	flashes := make(map[string]FlashMessage)
	id, ok := session.Values["user"].(string)
	if ok {
		u, err := UserR.FindOneByIdHex(id)
		if err != nil {
			flashes["no_session"] = FlashMessage{"danger", "You are not logged in"}
			data["flashes"] = flashes
			data["redirect"] = "/user/login"
		} else {
			p := new(Profile)
			utility.ReadJson(r, &p)
			u.UserProfile = p
			u.Update()
			data["success"] = true
			flashes["profile_updated"] = FlashMessage{"success", "Your Profile has been updated"}
			data["flashes"] = flashes
		}
	}
	utility.WriteJson(w, data)
}

func ResetRequestHandler(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	flashes := make(map[string]FlashMessage)
	tc := struct {
		Email string `json:"email"`
	}{}
	utility.ReadJson(r, &tc)
	tc.Email = strings.Trim(tc.Email, " ")
	user, err := UserR.FindOneByEmail(tc.Email)
	if err != nil {
		flashes["user_not_found"] = FlashMessage{"danger", "This user does not exist"}
	} else {
		user.CreateResetToken()
		flashes["success"] = FlashMessage{"success", "An Email has been sent to " + tc.Email + ". Please check your mailbox."}
	}
	data["flashes"] = flashes
	utility.WriteJson(w, data)
}

func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	flashes := make(map[string]FlashMessage)
	tc := struct {
		Token string `json:"token"`
	}{}
	utility.ReadJson(r, &tc)
	tc.Token = strings.Trim(tc.Token, " ")
	if tc.Token != "" {
		user, err := UserR.FindOneByResetToken(tc.Token)
		if err != nil {
			flashes["user_not_found"] = FlashMessage{"danger", "Invalid token"}
		} else {
			s := user.ResetPassword()
			if s == true {
				flashes["success"] = FlashMessage{"success", "An Email with your new password has been sent to " + user.Email + ". Please check your mailbox."}
			} else {
				flashes["token_expired"] = FlashMessage{"danger", "The Token expired. Please request a new password reset token."}
			}
		}
		data["flashes"] = flashes
		utility.WriteJson(w, data)
	}
}

func LoginStatusHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "p")
	data := make(map[string]interface{})
	id, ok := session.Values["user"].(string)
	if ok {
		u, err := UserR.FindOneByIdHex(id)
		if err != nil {
		} else {
			data["name"] = u.UserProfile.Name
		}
	}
	utility.WriteJson(w, data)
}
