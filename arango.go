package arango

// Refer https://www.arangodb.com/docs/2.8/http-user-management.html
// for additional details on the HTTP APIs exposed by Arangodb for
// user management
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
	"io/ioutil"
	"net/http"
	"time"
)

// changes begin

var (
	MetadataLen       int = 10
	LegacyMetadataLen int = 4
	UsernameLen       int = 32
	LegacyUsernameLen int = 16
)

var _ dbplugin.Database = (*Arango)(nil)

//entry
// Run instantiates a MySQL object, and runs the RPC server for the plugin
func Run(apiTLSConfig *api.TLSConfig) error {
	return runCommon(apiTLSConfig)
}

func runCommon(apiTLSConfig *api.TLSConfig) error {
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

// SQLConnectionProducer implements ConnectionProducer and provides a generic producer for most sql databases
type Arango struct {
	Url         string
	Username    string
	Password    string
	Host        string
	Port        string
	Initialized bool
	*connutil.SQLConnectionProducer
	credsutil.CredentialsProducer
}

func (a *Arango) Type() (string, error) {
	return "mysql", nil
}

func (a *Arango) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	return nil
}

func (a *Arango) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	return nil
}

func (a *Arango) RotateRootCredentials(ctx context.Context, statements []string) (config map[string]interface{}, err error) {
	return nil, nil
}

func (a *Arango) SetCredentials(ctx context.Context, statements dbplugin.Statements, staticConfig dbplugin.StaticUserConfig) (username string, password string, err error) {
	return "gary", "test", nil
}

func (a *Arango) Init(ctx context.Context, conf map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {
	urlValue, ok := conf["connection_url"]
	userValue, ok := conf["username"]
	passValue, ok := conf["password"]
	hostValue, ok := conf["host"]
	portValue, ok := conf["port"]
	if !ok {
		return nil, fmt.Errorf("")
	}
	a.Url = fmt.Sprint(urlValue)
	a.Username = fmt.Sprint(userValue)
	a.Password = fmt.Sprint(passValue)
	a.Host = fmt.Sprint(hostValue)
	a.Port = fmt.Sprint(portValue)

	// Set initialized to true at this point since all fields are set,
	// and the connection can be established at a later time.
	a.Initialized = true

	if verifyConnection {
		usernames, err := a.verify()

		if err != nil {
			fmt.Println("Error in getAllUsers: ", err.Error())
		}
		fmt.Println("Users in arangodb: ", usernames)
	}

	return conf, nil
}

func (a *Arango) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	username, err = a.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", err
	}

	password, err = a.GeneratePassword()
	if err != nil {
		return "", "", err
	}

	createUser(username, password)
	deleteUser(username)

	return username, password, nil
}

func (a *Arango) verify() ([]string, error) {
	usernames := make([]string, 1)

	// Formulate req with required headers
	// GET /_api/user/
	url := fmt.Sprintf("http://%s:%s/%s", a.Host, a.Port, pathUserMgmt)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error in NewRequest: ", err.Error())
		return nil, err
	}
	req.SetBasicAuth(a.Username, a.Password)
	req.Header.Add("Accept", "application/json")

	// Send req
	arangoClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := arangoClient.Do(req)
	if err != nil {
		fmt.Println("Error in req.Do: ", err.Error())
		return nil, err
	}

	// Process response
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var users ArangoUsers
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error in ReadAll: ", err.Error())
			return nil, err
		}
		err = json.Unmarshal(body, &users)
		if err != nil {
			fmt.Println("Error in Marshall: ", err.Error())
			return nil, err
		}
		for _, user := range users.Result {
			usernames = append(usernames, user.User)
		}
	} else {
		return nil, processErr(resp.StatusCode)
	}
	return usernames, nil
}

// change end

const (
	host         string = "192.168.1.24"
	port         int    = 8529
	pathUserMgmt string = "_api/user"
	// user 'root' is the default arango user with 'rw' access to '_system' db
	adminUserName string = "root"
	adminPassword string = "root"
)

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

// grantAccess grants 'user' either 'rw', 'ro' or 'none'
// access to 'dbname'
func grantAccess(username, dbname, grantStr string) error {
	// Marshal grant
	grant := &Grant{
		Grant: grantStr,
	}
	grantjson, err := json.Marshal(grant)
	if err != nil {
		fmt.Println("Error in Marshal: ", err.Error())
		return err
	}

	// Formulate req with required headers
	// PUT /_api/user/{user}/database/{dbname}
	url := fmt.Sprintf("http://%s:%d/%s/%s/database/%s", host, port, pathUserMgmt, username, dbname)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(grantjson))
	if err != nil {
		fmt.Println("Error in NewRequest: ", err.Error())
		return err
	}
	req.SetBasicAuth(adminUserName, adminPassword)
	req.Header.Add("Accept", "application/json")

	// Send req
	arangoClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := arangoClient.Do(req)
	if err != nil {
		fmt.Println("Error in req.Do: ", err.Error())
		return err
	}

	// Process response
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("User %s granted %s access to %s\n", username, grantStr, dbname)
		return nil
	} else {
		return processErr(resp.StatusCode)
	}
}

// createUser creates 'username' with password 'password'
// in arangodb. Creating a user
func createUser(username string, password string) error {
	// Marshal username & password
	userCred := &UserCredential{
		User:     username,
		Password: password,
	}
	userjson, err := json.Marshal(userCred)
	if err != nil {
		fmt.Println("Error in Marshal: ", err.Error())
		return err
	}

	// Formulate req with required headers
	// POST /_api/user
	url := fmt.Sprintf("http://%s:%d/%s", host, port, pathUserMgmt)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(userjson))
	if err != nil {
		fmt.Println("Error in NewRequest: ", err.Error())
		return err
	}
	req.SetBasicAuth(adminUserName, adminPassword)
	req.Header.Add("Accept", "application/json")

	// Send req
	arangoClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := arangoClient.Do(req)
	if err != nil {
		fmt.Println("Error in req.Do: ", err.Error())
		return err
	}

	// Process response
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		fmt.Printf("User %s created successfully\n", username)
		return nil
	} else {
		return processErr(resp.StatusCode)
	}
}

// deleteUser deletes 'username' from arangodb
func deleteUser(username string) error {
	// Formulate req with required headers
	// DELETE /_api/user/{user}
	url := fmt.Sprintf("http://%s:%d/%s/%s", host, port, pathUserMgmt, username)
	fmt.Println(url)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		fmt.Println("Error in NewRequest: ", err.Error())
		return err
	}
	req.SetBasicAuth(adminUserName, adminPassword)
	req.Header.Add("Accept", "application/json")

	// Send req
	arangoClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := arangoClient.Do(req)
	if err != nil {
		fmt.Println("Error in req.Do: ", err.Error())
		return err
	}

	// Process response
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		fmt.Printf("User %s deleted successfully\n", username)
		return nil
	} else {
		return processErr(resp.StatusCode)
	}
}

func getAllUsers() ([]string, error) {
	usernames := make([]string, 1)

	// Formulate req with required headers
	// GET /_api/user/
	url := fmt.Sprintf("http://%s:%d/%s", host, port, pathUserMgmt)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error in NewRequest: ", err.Error())
		return nil, err
	}
	req.SetBasicAuth(adminUserName, adminPassword)
	req.Header.Add("Accept", "application/json")

	// Send req
	arangoClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := arangoClient.Do(req)
	if err != nil {
		fmt.Println("Error in req.Do: ", err.Error())
		return nil, err
	}

	// Process response
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var users ArangoUsers
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error in ReadAll: ", err.Error())
			return nil, err
		}
		err = json.Unmarshal(body, &users)
		if err != nil {
			fmt.Println("Error in Marshall: ", err.Error())
			return nil, err
		}
		for _, user := range users.Result {
			usernames = append(usernames, user.User)
		}
	} else {
		return nil, processErr(resp.StatusCode)
	}
	return usernames, nil
}

func main() {
	// Create a new user
	err := createUser("test2", "test2password")
	if err != nil {
		fmt.Println("Error in createUser: ", err.Error())
	}

	// Grant user, 'test' 'rw' access to 'testdb'
	err = grantAccess("test2", "testdb", "rw")
	if err != nil {
		fmt.Println("Error in grantAccess: ", err.Error())
	}

	// List all provisioned arangodb users
	usernames, err := getAllUsers()
	if err != nil {
		fmt.Println("Error in getAllUsers: ", err.Error())
	}
	fmt.Println("Users in arangodb: ", usernames)

	// Delete a new user
	err = deleteUser("test2")
	if err != nil {
		fmt.Println("Error in deleteUser: ", err.Error())
	}

	// List all provisioned arangodb users
	usernames, err = getAllUsers()
	if err != nil {
		fmt.Println("Error in getAllUsers: ", err.Error())
	}
	fmt.Println("Users in arangodb: ", usernames)
}
