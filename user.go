package user

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"labix.org/v2/mgo"
)

var (
	Config       *Conf
	Router       *mux.Router
	UserDB       *mgo.Database
	UserR        *UserRepository = new(UserRepository)
	mgoSession   *mgo.Session
	sessionStore *sessions.CookieStore
)

type Conf struct {
	Host         string // Host or rather domain name example.com
	MailFrom     string // Mail From address, can be "Name <web@example.com>" w/o quotes
	DBName       string // Mongo Database Name
	DBCollection string // Name of the User collection, typically "user"
}

func New(ms *mgo.Session, ss *sessions.CookieStore, host, mailfrom, dbname, dbcollection string) {
	mgoSession = ms.Clone()
	sessionStore = ss
	Config = &Conf{
		Host:         host,
		MailFrom:     mailfrom,
		DBName:       dbname,
		DBCollection: dbcollection,
	}
	UserDB = mgoSession.DB(Config.DBName)
	UserR.Collection = UserDB.C(Config.DBCollection)
	Router.HandleFunc("/user/register", RegisterHandler).Methods("POST")
	Router.HandleFunc("/user/authenticate", AuthenticateHandler).Methods("POST")
	Router.HandleFunc("/user/endsession", LogoutHandler).Methods("POST")
	Router.HandleFunc("/user/profile", ProfileHandler).Methods("GET")
	Router.HandleFunc("/user/profile", UpdateProfileHandler).Methods("POST")
	Router.HandleFunc("/user/reset_request", ResetRequestHandler).Methods("POST")
	Router.HandleFunc("/user/reset_password", ResetPasswordHandler).Methods("POST")
	Router.HandleFunc("/user/loginstatus", LoginStatusHandler).Methods("GET")
}
