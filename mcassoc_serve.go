package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	mcassoc "github.com/lukegb/mcassoc/mcassoc"
	minecraft "github.com/lukegb/mcassoc/minecraft"
	mojang "github.com/lukegb/mcassoc/mojang"
	statkeeper "github.com/lukegb/mcassoc/statkeeper"
	"html/template"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

var sesskey []byte
var dvKey []byte
var authenticator mcassoc.Associfier
var httplistenloc string
var profileClient *minecraft.ProfileClient

type TemplatePageData struct {
	Title string
}

type TemplateData struct {
	PageData TemplatePageData
	Data     interface{}
}

type SigningData struct {
	Username string `json:"username"`
	UUID     string `json:"uuid"`
	Now      int64  `json:"now"`
	Key      string `json:"key"`
}

type SkinColourBit struct {
	Background string
	Text       string
	Link       string
}

type SkinColour struct {
	Border SkinColourBit
	Box    SkinColourBit
	Main   SkinColourBit

	Button SkinColourBit

	Branding bool
}

func generateSharedKey(siteid string) []byte {
	z := hmac.New(sha512.New, sesskey)
	z.Write([]byte(siteid))
	key := z.Sum([]byte{})
	return key
}

func generateDomainVerificationKey(domain string, ip string, sessionId string) []byte {
	z := hmac.New(sha512.New, dvKey)
	t := time.Now()
	keyContents := domain + t.Format("20060102") + ip + sessionId
	z.Write([]byte(keyContents))
	key := z.Sum([]byte("  ")) // pad it so we never get equals signs (TXT records love those)
	return key
}

func generateDataBlob(data SigningData, siteid string) string {
	databytes, _ := json.Marshal(data)
	datahash := generateHashOfBlob(databytes, siteid, true)
	return base64.StdEncoding.EncodeToString(datahash)
}
func generateHashOfBlob(data []byte, siteid string, doappend bool) []byte {
	skey := generateSharedKey(siteid)
	x := hmac.New(sha1.New, skey)
	x.Write(data)
	if doappend {
		return x.Sum(data)
	}
	return x.Sum([]byte{})
}

type Gettable interface {
	Get(key string) string
}

func getOr(vs Gettable, what string, def string) string {
	val := vs.Get(what)
	if val == "" {
		return def
	}
	return val
}

func isDomainValid(domain string) bool {
	_, err := net.LookupIP(domain)
	if err != nil {
		return false
	}
	return true
}

func getDomainVerificationUrl(domain string, code string) string {
	return "http://" + domain + "/mcassoc-" + code + ".txt"
}

func unwrapSkinColour(vs Gettable) SkinColour {
	return SkinColour{
		Border: SkinColourBit{
			Background: getOr(vs, "c:bdr:b", "darkblue"),
			Text:       getOr(vs, "c:bdr:t", "white"),
			Link:       getOr(vs, "c:bdr:l", "white"),
		},
		Box: SkinColourBit{
			Background: getOr(vs, "c:box:b", "skyblue"),
			Text:       getOr(vs, "c:box:t", "black"),
			Link:       getOr(vs, "c:bdr:l", "black"),
		},
		Main: SkinColourBit{
			Background: getOr(vs, "c:mn:b", "white"),
			Text:       getOr(vs, "c:mn:t", "black"),
			Link:       getOr(vs, "c:mn:l", "black"),
		},
		Button: SkinColourBit{
			Background: getOr(vs, "c:btn:b", "#0078e7"),
			Text:       getOr(vs, "c:btn:t", "white"),
			Link:       "ignored",
		},
		Branding: getOr(vs, "showBranding", "true") != "false",
	}
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("templates/frontbase.html", "templates/signup.html"))

	t.ExecuteTemplate(w, "layout", TemplateData{
		PageData: TemplatePageData{
			Title: "Minecraft Account Association",
		},
		Data: struct {
			HasError bool
		}{
			HasError: r.FormValue("err") == "domain",
		},
	})
}

func getActualRemoteAddr(r *http.Request) string {
	// We get the port which we want to strip out
	return strings.Split(r.RemoteAddr, ":")[0]
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	//TODO: DRY
	sessionId := addSessionIdIfNotExists(w, r)
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("must be a POST request"))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("data invalid"))
		return
	}
	domain := r.Form.Get("domain")
	if !isDomainValid(domain) {
		http.Redirect(w, r, "/?err=domain", 301)
		return
	}

	data := generateDomainVerificationKey(domain, getActualRemoteAddr(r), sessionId)

	t := template.Must(template.ParseFiles("templates/frontbase.html", "templates/verification.html"))
	value := base64.URLEncoding.EncodeToString(data)
	t.ExecuteTemplate(w, "layout", TemplateData{
		PageData: TemplatePageData{
			Title: "Minecraft Account Association",
		},
		Data: struct {
			Key        string
			URL        string
			UserDomain string
		}{
			Key:        value,
			URL:        "http://" + domain + "/mcassoc-" + value + ".txt",
			UserDomain: domain,
		},
	})
}

func ApiDomainVerificationDns(w http.ResponseWriter, r *http.Request) {
	domain := r.Form.Get("domain")
	var txtContentsArray []string
	var err error
	txtContentsArray, err = net.LookupTXT("mcassocverify." + domain)
	if len(txtContentsArray) != 1 {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Invalid number of TXT records (" + fmt.Sprintf("%v", len(txtContentsArray)) + ") for name " + "mcassocverify." + domain + "."))
		if len(txtContentsArray) == 0 {
			w.Write([]byte(" If you've just added this record, it can take a while for DNS changes to propagate."))
		}
		return
	}
	var txtContents string
	txtContents = txtContentsArray[0]
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("An error was encountered while attempting to lookup the TXT record. Ensure it exists and try again later."))
		return
	}

	key := "code=" + base64.URLEncoding.EncodeToString(generateDomainVerificationKey(domain, getActualRemoteAddr(r), getSessionId(r)))
	if key != txtContents {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("The TXT record contents was " + txtContents + " but the expected value was " + key))
		return
	}

	w.Write([]byte(hex.EncodeToString(generateSharedKey(domain))))

}

func addSessionIdIfNotExists(w http.ResponseWriter, r *http.Request) string {
	if !hasSessionId(r) {
		return generateSessionId(w)
	}
	return getSessionId(r)
}

func hasSessionId(r *http.Request) bool {
	return getSessionId(r) != ""
}

func getSessionId(r *http.Request) string {
	cookie, err := r.Cookie("SessionId")
	if err == nil && cookie != nil {
		return cookie.Value
	}
	return ""
}

func generateSessionId(w http.ResponseWriter) string {
	bytes := make([]byte, 10)

	_, err := rand.Read(bytes)
	if err != nil {
		log.Println("Random generation failed.")
	}
	stringId := base64.URLEncoding.EncodeToString(bytes)
	cookie := &http.Cookie{Name: "SessionId", Value: stringId, HttpOnly: true}
	http.SetCookie(w, cookie)
	return stringId
}

func ApiDomainVerification(w http.ResponseWriter, r *http.Request) {
	if !hasSessionId(r) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Cookies must be enabled to perform verification."))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("data invalid"))
		return
	}

	if r.Form.Get("verificationType") == "txt" {
		ApiDomainVerificationDns(w, r)
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")

		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("must be a POST request"))
		return
	}

	domain := r.Form.Get("domain")
	key := base64.URLEncoding.EncodeToString(generateDomainVerificationKey(domain, getActualRemoteAddr(r), getSessionId(r)))
	url := getDomainVerificationUrl(domain, key)
	var resp *http.Response
	resp, err = http.Get(url)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("An error was encountered in opening a connection."))
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("URL must return HTTP 200 in response to GET. URL visited was " + url))
		return
	}

	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil || strings.TrimSpace(string(contents)) != key {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Please ensure the file contains the key and no extra characters."))
		return
	}

	w.Write([]byte(hex.EncodeToString(generateSharedKey(domain))))
}

func TestPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("must be a POST request"))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("data invalid"))
		return
	}

	data := r.Form.Get("data")
	databytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		w.Write([]byte("invalid base64 data"))
		return
	}

	if len(databytes) < 20 {
		w.Write([]byte("data too short?!?"))
		return
	}
	sigbytes := databytes[len(databytes)-20:]
	databytes = databytes[:len(databytes)-20]

	mysigbytes := generateHashOfBlob(databytes, "_", false)
	sigok := subtle.ConstantTimeCompare(sigbytes, mysigbytes) == 1
	sigokchar := "no"
	if sigok {
		sigokchar = "yes"
	}

	w.Write([]byte("\ndata: "))
	w.Write(databytes)
	w.Write([]byte("\nsignature OK? " + sigokchar))
	if sigok {
		dataobj := new(SigningData)
		err := json.Unmarshal(databytes, dataobj)
		if err != nil {
			w.Write([]byte("\nfailed to unmarshal JSON: " + err.Error()))
		} else {
			w.Write([]byte("\nunmarshalled OK"))
			tsfresh := "no"
			now := time.Now().UTC().Unix()
			if dataobj.Now > (now-30) && dataobj.Now < (now+30) {
				tsfresh = fmt.Sprintf("yes (%d seconds old)", now-dataobj.Now)
			}
			w.Write([]byte("\ntimestamp 'fresh'? " + tsfresh))
		}
	}
}

func PerformPage(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	siteID := v.Get("siteid")
	postbackURL := v.Get("postback")
	key := v.Get("key")
	mcuser := v.Get("mcusername")

	skinColours := unwrapSkinColour(v)

	if pbu, err := url.Parse(postbackURL); err != nil || (pbu.Scheme != "http" && pbu.Scheme != "https") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("postback must be a HTTP/HTTPS url"))
		return
	}

	// check that the required fields are set
	if siteID == "" || postbackURL == "" || key == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("required parameter(s) missing"))
		return
	}

	t := template.Must(template.ParseFiles("templates/minibase.html", "templates/perform.html"))

	statkeeper.GLOBAL.NewAssocAttempt()

	t.ExecuteTemplate(w, "layout", TemplateData{
		PageData: TemplatePageData{
			Title: "Minecraft Account Association",
		},
		Data: struct {
			SiteID      string
			PostbackURL string
			Key         string
			MCUser      string
			SkinColour  SkinColour
		}{
			SiteID:      siteID,
			PostbackURL: postbackURL,
			Key:         key,
			MCUser:      mcuser,
			SkinColour:  skinColours,
		},
	})
}

func ApiCheckUserPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("must be a POST request"))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("data invalid"))
		return
	}

	je := json.NewEncoder(w)

	mcusername := r.Form.Get("mcusername")

	// get their uuid from mojang
	user, err := mojang.GetProfileByUsername(mcusername)
	if err != nil {
		if err == mojang.ERR_NO_SUCH_USER {
			je.Encode(struct {
				Error string `json:"error"`
			}{
				Error: "no such user",
			})
			return
		} else {
			statkeeper.GLOBAL.MojangRequestFail()
			statkeeper.GLOBAL.AssocFail()
			log.Println("error while getting mojang profile", mcusername, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		statkeeper.GLOBAL.MojangRequestOK()
	}

	// so we can get their skin data
	mcprofile, err := profileClient.GetProfile(user.Id)
	if err != nil {
		statkeeper.GLOBAL.McRequestOK()
		log.Println("error while getting minecraft profile", mcusername, user.Id, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		statkeeper.GLOBAL.McRequestFail()
		statkeeper.GLOBAL.AssocFail()
	}

	// so we can get their skin
	skinim, err := minecraft.GetSkin(mcprofile)
	if err != nil {
		log.Println("error while getting skin", mcusername, user.Id, mcprofile, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// so we can check if it has a datablock in it
	je.Encode(struct {
		MCUsername string `json:"mcusername"`
		UUID       string `json:"uuid"`
		Exists     bool   `json:"exists"`
	}{
		MCUsername: mcusername,
		UUID:       user.Id,
		Exists:     mcassoc.HasDatablock(skinim),
	})
}

func ApiAuthenticateUserPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("must be a POST request"))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("data invalid"))
		return
	}

	je := json.NewEncoder(w)

	uuid := r.Form.Get("uuid")
	password := r.Form.Get("password")

	mcprofile, err := profileClient.GetProfile(uuid)
	if err != nil {
		statkeeper.GLOBAL.McRequestFail()
		statkeeper.GLOBAL.AssocFail()
		log.Println("error while getting minecraft profile", uuid, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		statkeeper.GLOBAL.McRequestOK()
	}

	skinim, err := minecraft.GetSkin(mcprofile)
	if err != nil {
		log.Println("error while getting skin", uuid, mcprofile, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	passwordok, err := authenticator.Verify(password, skinim)
	if err != nil {
		log.Println("error verifying datablock", uuid, mcprofile, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	postbackurl := ""
	postbackdata := ""
	if passwordok {
		// yay!
		postbackstr := r.Form.Get("data[postback]")
		postback, err := url.Parse(postbackstr)
		if err != nil || (postback.Scheme != "http" && postback.Scheme != "https") {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}

		postbackdata = generateDataBlob(SigningData{
			Now:      time.Now().UTC().Unix(),
			UUID:     mcprofile.Id,
			Username: mcprofile.Name,
			Key:      r.Form.Get("data[key]"),
		}, r.Form.Get("data[siteid]"))
		postbackurl = postback.String()

		statkeeper.GLOBAL.AssocComplete()
	}

	je.Encode(struct {
		MCUsername   string `json:"mcusername"`
		UUID         string `json:"uuid"`
		Correct      bool   `json:"correct"`
		Postback     string `json:"postback"`
		PostbackData string `json:"postbackdata"`
	}{
		MCUsername:   mcprofile.Name,
		UUID:         mcprofile.Id,
		Correct:      passwordok,
		Postback:     postbackurl,
		PostbackData: postbackdata,
	})
}

func ApiCreateUserPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("must be a POST request"))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("data invalid"))
		return
	}

	je := json.NewEncoder(w)

	uuid := r.Form.Get("uuid")
	password := r.Form.Get("password")

	mcprofile, err := profileClient.GetProfile(uuid)
	if err != nil {
		statkeeper.GLOBAL.McRequestFail()
		statkeeper.GLOBAL.AssocFail()
		log.Println("error while getting minecraft profile", uuid, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		statkeeper.GLOBAL.McRequestOK()
	}

	skinim, err := minecraft.GetSkin(mcprofile)
	if err != nil {
		log.Println("error while getting skin", uuid, mcprofile, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	authedim, err := authenticator.Embed(password, skinim)
	if err != nil {
		log.Println("error while embedding into skin", uuid, mcprofile, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tmpf, err := ioutil.TempFile("tmpskin/", uuid)
	if err != nil {
		log.Println("error while opening temp file", uuid, mcprofile, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer tmpf.Close()

	err = png.Encode(tmpf, authedim)
	if err != nil {
		log.Println("error while writing authed skin image", uuid, mcprofile, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	je.Encode(struct {
		Filename string `json:"filename"`
	}{
		Filename: path.Base(tmpf.Name()),
	})
}

func SkinServerPage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	f, err := os.Open(fmt.Sprintf("tmpskin/%s", vars["filename"]))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Add("Content-Type", "image/png")
	io.Copy(w, f)
}

func myinit() {
	var flagSesskey string
	var flagAuthenticationKey string
	var flagStatHatKey string
	var flagDomainVerificationKey string
	flag.StringVar(&flagSesskey, "sesskey", "insecure", "session key (used for creating shared secrets with clients)")
	flag.StringVar(&flagAuthenticationKey, "authkey", "insecure", "authentication key (used for hashing passwords)")
	flag.StringVar(&flagStatHatKey, "stathat_key", "", "stathat key (used for statistics)")
	flag.StringVar(&flagDomainVerificationKey, "dvkey", "insecure", "domain verification key (used for verifying domain ownership)")
	flag.StringVar(&httplistenloc, "listen", ":21333", "HTTP listener location")
	flag.Parse()

	// load the authentication keys
	sesskey = []byte(flagSesskey)
	dvKey = []byte(flagDomainVerificationKey)
	authenticator = mcassoc.NewAssocifier(flagAuthenticationKey)
	profileClient = minecraft.NewProfileClient()

	if flagStatHatKey != "" {
		log.Println("Initialising statistics with key", flagStatHatKey)
		sh := statkeeper.NewStatHatStatKeeper(flagStatHatKey)
		statkeeper.GLOBAL = sh
	}

	log.Println("Set session key", flagSesskey)
	log.Println("Set authentication key", flagAuthenticationKey)
	log.Println("Set domain verification key", flagDomainVerificationKey)
	log.Println("Going to listen at", httplistenloc)

}

func main() {
	myinit()

	r := mux.NewRouter()
	r.HandleFunc("/", HomePage)
	r.HandleFunc("/signup", SignUp)
	r.HandleFunc("/perform", PerformPage)
	r.HandleFunc("/test", TestPage)
	r.HandleFunc("/api/domain/verify", ApiDomainVerification)
	r.HandleFunc("/api/user/check", ApiCheckUserPage)
	r.HandleFunc("/api/user/create", ApiCreateUserPage)
	r.HandleFunc("/api/user/authenticate", ApiAuthenticateUserPage)
	r.HandleFunc("/media/skin/{filename:[0-9a-z]+}.png", SkinServerPage)
	r.PathPrefix("/static/").Handler(http.FileServer(http.Dir("./templates/")))
	r.PathPrefix("/css/").Handler(http.FileServer(http.Dir("./templates/")))
	r.PathPrefix("/img/").Handler(http.FileServer(http.Dir("./templates/")))
	http.Handle("/", r)

	log.Println("Running!")
	err := http.ListenAndServe(httplistenloc, nil)
	if err != nil {
		log.Fatal("http.ListenAndServe: ", err)
	}
}
