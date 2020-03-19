package arango

// Custom Arango DB plugin for HashiCorp Vault. It implemented required Database interface.
// Refer https://www.vaultproject.io/docs/secrets/databases/custom/.
// For Arango HTTP API, refer https://www.arangodb.com/docs/stable/http/.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"log"
	"log/syslog"
	"net/http"
	"sync"
	"time"
)

const (
	MetadataLen  int    = 10
	UsernameLen  int    = 32
	pathUserMgmt string = "_api/user"
	pathSystemDB string = "_db/_system/_api/database"
	// connection availability check
	pathSystemTime string = "_db/_system/_admin/time"
)

var _ dbplugin.Database = (*Arango)(nil)

var (
	// ErrBadRequest is returned when arangodb returns http.StatusBadRequest (typically due to some invalid json data)
	ErrBadRequest = errors.New("BadRequest")
	// ErrForbidden is returned when arangodb returns http.StatusForbidden
	ErrForbidden = errors.New("Forbidden")
	// ErrUnauthorized is returned when arangodb returns http.StatusUnauthorized
	ErrUnauthorized = errors.New("Unauthorized")
	// ErrUserExists is returned when arangodb returns http.StatusConflict
	ErrUserExists = errors.New("User exists")
	// ErrUnexpected is returned when arangodb returns an unexpected http StatusCode
	ErrUnexpected = errors.New("Unexpected status code")
	// ErrNotFound is returned when arangodb returns http.StatusNotFound
	ErrNotFound = errors.New("NotFound")
)

// SQLConnectionProducer implements ConnectionProducer and provides a generic producer for most sql databases
type Arango struct {
	// syslog server for this plugin log
	SyslogURL   string
	Username    string
	Password    string
	Host        string
	Port        string
	Initialized bool
	*connutil.SQLConnectionProducer
	credsutil.CredentialsProducer
	sync.Mutex
}

// UserCredential to be marshalled and sent to arango
// to create users
type UserCredential struct {
	User     string `json:"user"`
	Password string `json:"passwd"`
}

// Grant to be marshalled and sent to arango
// to grant users access to resources. Grant
// could be 'ro', 'rw' or 'none' (i.e. no access)
// Per Arango documentation:
//	rw 		-> Administrate
//  ro 		-> Access
//  none 	-> No Access
type Grant struct {
	Grant string `json:"grant"`
}

// ArangoUser represents per-user data in Arnagodb
type ArangoUser struct {
	User   string `json:"user"`
	Active bool   `json:"active"`
	//Extra  string `json: "extra"`
}

// ArangoUsers represents collection of ArangoUsers
type ArangoUsers struct {
	Error  bool         `json:"error"`
	Code   int          `json:"code"`
	Result []ArangoUser `json:"result"`
}

type Database struct {
	Name  string `json:"name"`
	Users []struct {
		Active   bool   `json:"active"`
		Username string `json:"username"`
		Passwd   string `json:"passwd"`
	} `json:"users"`
}

//entry
// Run instantiates a Arango object, and runs the RPC server for the plugin
func Run(apiTLSConfig *api.TLSConfig) error {
	var f func() (interface{}, error)

	f = New(MetadataLen, MetadataLen, UsernameLen)

	dbType, err := f()
	if err != nil {
		return err
	}

	dbplugin.Serve(dbType.(dbplugin.Database), api.VaultPluginTLSProvider(apiTLSConfig))

	return nil
}

// New implements builtinplugins.BuiltinFactory
func New(displayNameLen, roleNameLen, usernameLen int) func() (interface{}, error) {
	return func() (interface{}, error) {
		db := new(displayNameLen, roleNameLen, usernameLen)
		// Wrap the plugin with middleware to sanitize errors
		dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.SecretValues)

		return dbType, nil
	}
}

func new(displayNameLen, roleNameLen, usernameLen int) *Arango {
	connProducer := &connutil.SQLConnectionProducer{}
	connProducer.Type = "mysql"

	credsProducer := &credsutil.SQLCredentialsProducer{
		DisplayNameLen: displayNameLen,
		RoleNameLen:    roleNameLen,
		UsernameLen:    usernameLen,
		Separator:      "-",
	}

	return &Arango{
		SQLConnectionProducer: connProducer,
		CredentialsProducer:   credsProducer,
	}
}

// Database interface function: Type returns the TypeName for the particular database backend implementation
func (a *Arango) Type() (string, error) {
	return "arango", nil
}

// Database interface function: RenewUser is triggered by a renewal call to the API. In many database
// backends, this triggers a call on the underlying database that extends a VALID UNTIL clause on a user.
func (a *Arango) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	go a.writeLog("called RenewUser. It's not implemented")
	return nil
}

// Database interface function: RotateRootCredentials is triggered by a root credential rotation call to the API.
func (a *Arango) RotateRootCredentials(ctx context.Context, statements []string) (config map[string]interface{}, err error) {
	go a.writeLog("Arango Vault Plugin: called RotateRootCredentials")
	return nil, nil
}

// Database interface function: SetCredentials uses provided information to create or set the credentials
// for a database user. Unlike CreateUser, this method requires both a
// username and a password given instead of generating them. This is used for
// creating and setting the password of static accounts, as well as rolling
// back passwords in the database in the event an updated database fails to
// save in Vault's storage.
func (a *Arango) SetCredentials(ctx context.Context, statements dbplugin.Statements, staticConfig dbplugin.StaticUserConfig) (username string, password string, err error) {
	go a.writeLog("Arango Vault Plugin: called SetCredentials ")
	return "", "", nil
}

// Database interface function: Init is called on `$ vault write database/config/:db-name`, or when you
// do a creds call after Vault's been restarted. The config provided won't
// hold all the keys and values provided in the API call, some will be
// stripped by the database engine before the config is provided. The config
// returned will be stored, which will persist it across shutdowns.
func (a *Arango) Init(ctx context.Context, conf map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {
	a.Lock()
	defer a.Unlock()

	urlValue, ok := conf["syslog_url"]
	if !ok {
		// default to local syslog for development
		a.SyslogURL = "localhost:2514"
	} else {
		a.SyslogURL = fmt.Sprint(urlValue)
	}
	userValue, ok := conf["username"]
	if !ok {
		return nil, fmt.Errorf("")
	}
	passValue, ok := conf["password"]
	if !ok {
		return nil, fmt.Errorf("")
	}
	hostValue, ok := conf["host"]
	if !ok {
		return nil, fmt.Errorf("")
	}
	portValue, ok := conf["port"]
	if !ok {
		return nil, fmt.Errorf("")
	}

	a.Username = fmt.Sprint(userValue)
	a.Password = fmt.Sprint(passValue)
	a.Host = fmt.Sprint(hostValue)
	a.Port = fmt.Sprint(portValue)

	// Set initialized to true at this point since all fields are set,
	// and the connection can be established at a later time.
	a.Initialized = true
	if verifyConnection {
		err := a.verify()
		if err != nil {
			return conf, err
		}
	}

	go a.writeLog("Arango Vault Plugin: Init finished")
	return conf, nil
}

// Database interface function: CreateUser is called on `$ vault read database/creds/:role-name` and it's
// also the first time anything is touched from `$ vault write database/roles/:role-name`.
// Currently it supports two cases:
// 1. db name is provided, create this db and assign the credential to newly created db.
// 2. db name is NOT provided, create the credential only with no permission to any database.
func (a *Arango) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	go a.writeLog("called CreateUser")

	username, err = a.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", err
	}

	password, err = a.GeneratePassword()
	if err != nil {
		return "", "", err
	}

	statements = dbutil.StatementCompatibilityHelper(statements)
	if len(statements.Creation) == 0 {
		go a.writeLog("CreateUser: no database name passed in, only creating user: " + username)
		err = a.createNewUser(username, password)
		if err != nil {
			return username, password, err
		}
		return username, password, nil
	}

	// hardcode the first statement is database name, e.g.: cokeDB
	databaseName := statements.Creation[0]
	go a.writeLog("passed in database name: " + databaseName)

	err = a.creatDatabaseAndSetupCredential(username, password, databaseName)
	if err != nil {
		return username, password, err
	}
	return username, password, nil
}

// Database interface function: RevokeUser is triggered either automatically by a lease expiration, or by
// a revocation call to the API.
func (a *Arango) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	go a.writeLog("Arango Vault Plugin: called RevokeUser")

	statements = dbutil.StatementCompatibilityHelper(statements)
	if len(statements.Creation) != 0 {
		go a.writeLog("RevokeUser: no database name passed in, only deleting user: " + username)

		// hardcode the first statement is database name, e.g.: cokeDB
		databaseName := statements.Creation[0]
		go a.writeLog("passed in database name: " + databaseName)

		err := a.deleteDatabase(databaseName)
		if err != nil {
			return err
		}
	}

	err := a.deleteUser(username)
	if err != nil {
		return err
	}
	return nil
}

// Verify connection by called restricted API
func (a *Arango) verify() error {
	// check whether or not the connection is valid by getting Arango server time
	url := fmt.Sprintf("http://%s:%s/%s", a.Host, a.Port, pathSystemTime)
	req, err := http.NewRequest("GET", url, nil)
	resp, err2 := a.executeRequest(err, req)
	if err2 != nil {
		return err2
	}

	// Process response
	if resp.StatusCode != http.StatusOK {
		return processErr(resp.StatusCode)
	}
	return nil
}

// Create new database, account. And assign the new credential to the database.
func (a *Arango) creatDatabaseAndSetupCredential(username, password, dbname string) error {
	database := &Database{
		Name: dbname,
		Users: []struct {
			Active   bool   `json:"active"`
			Username string `json:"username"`
			Passwd   string `json:"passwd"`
		}{{Active: true, Username: username, Passwd: password}},
	}
	databaseJson, err := json.Marshal(database)
	if err != nil {
		go a.writeLog("Error in Marshal: " + err.Error())
		return err
	}

	// Formulate req with required headers
	// POST http://localhost:8529/_db/_system/_api/database
	//
	url := fmt.Sprintf("http://%s:%s/%s", a.Host, a.Port, pathSystemDB)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(databaseJson))
	if err != nil {
		go a.writeLog("Error in NewRequest: " + err.Error())
		return err
	}

	resp, err2 := a.executeRequest(err, req)
	if err2 != nil {
		return err2
	}

	// Process response
	if resp.StatusCode == http.StatusCreated {
		go a.writeLog("database " + dbname + " has been created for user " + username)
		return nil
	} else {
		return processErr(resp.StatusCode)
	}
}

// createUser creates 'username' with password 'password'
// in arangodb. Creating a user
func (a *Arango) createNewUser(username string, password string) error {
	// Marshal username & password
	userCred := &UserCredential{
		User:     username,
		Password: password,
	}
	userjson, err := json.Marshal(userCred)
	if err != nil {
		go a.writeLog("Error in Marshal: " + err.Error())
		return err
	}

	// Formulate req with required headers
	// POST /_api/user
	url := fmt.Sprintf("http://%s:%s/%s", a.Host, a.Port, pathUserMgmt)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(userjson))
	if err != nil {
		go a.writeLog("Error in NewRequest: " + err.Error())
		return err
	}
	resp, err2 := a.executeRequest(err, req)
	if err2 != nil {
		return err2
	}

	// Process response
	if resp.StatusCode == http.StatusCreated {
		go a.writeLog("Successfully created user: " + username)
		return nil
	} else {
		return processErr(resp.StatusCode)
	}
}

// deleteUser deletes 'username' from arangodb
func (a *Arango) deleteUser(username string) error {
	// Formulate req with required headers
	// DELETE /_api/user/{user}
	url := fmt.Sprintf("http://%s:%s/%s/%s", a.Host, a.Port, pathUserMgmt, username)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		go a.writeLog("Error in NewRequest: " + err.Error())
		return err
	}
	resp, err2 := a.executeRequest(err, req)
	if err2 != nil {
		return err2
	}

	// Process response
	if resp.StatusCode == http.StatusAccepted {
		go a.writeLog("Successfully deleted user: " + username)
		return nil
	} else {
		return processErr(resp.StatusCode)
	}
}

// Create new database, account. And assign the new credential to the database.
func (a *Arango) deleteDatabase(dbname string) error {
	// Formulate req with required headers
	// POST http://localhost:8529/_db/_system/_api/database
	url := fmt.Sprintf("http://%s:%s/%s/%s", a.Host, a.Port, pathSystemDB, dbname)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		go a.writeLog("Error in NewRequest: " + err.Error())
		return err
	}

	resp, err2 := a.executeRequest(err, req)
	if err2 != nil {
		return err2
	}

	// Process response
	if resp.StatusCode == http.StatusOK {
		go a.writeLog("database " + dbname + " has been deleted")
		return nil
	} else {
		return processErr(resp.StatusCode)
	}
}

func (a *Arango) writeLog(msg string) {
	sysLog, err := syslog.Dial("tcp", a.SyslogURL,
		syslog.LOG_WARNING|syslog.LOG_DAEMON, "vault")
	if err != nil {
		log.Println("local Arango Vault Plugin: " + msg)
		return
	}
	fmt.Fprintf(sysLog, "Arango Vault Plugin: "+msg)
}

func (a *Arango) executeRequest(err error, req *http.Request) (*http.Response, error) {
	if !a.Initialized {
		return nil, errors.New("arango Plugin is not initialized")
	}
	if err != nil {
		go a.writeLog("Error in NewRequest: " + err.Error())
		return nil, err
	}
	req.SetBasicAuth(a.Username, a.Password)
	req.Header.Add("Accept", "application/json")

	// Send req
	arangoClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := arangoClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		go a.writeLog("Error in req.Do: " + err.Error())
		return nil, err
	}
	return resp, nil
}

func processErr(code int) error {
	switch code {
	// 400
	case http.StatusBadRequest:
		return ErrBadRequest
	// 401
	case http.StatusUnauthorized:
		return ErrUnauthorized
	// 403
	case http.StatusForbidden:
		return ErrForbidden
	// 404
	case http.StatusNotFound:
		return ErrNotFound
	// 409
	case http.StatusConflict:
		return ErrUserExists
	default:
		return ErrUnexpected
	}
}
