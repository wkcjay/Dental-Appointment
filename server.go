package main

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Username string
	Password []byte
	First    string
	Last     string
}

type adminuser struct {
	Username string `json:"Username"`
	Password []byte `json:"Password"`
	First    string `json:"First"`
	Last     string `json:"Last"`
}
type Available struct {
	date string
	time []string
}

var (
	prevdate    string
	tpl         *template.Template
	mapUsers    = map[string]user{}
	mapSessions = map[string]string{}
	jsonuser    = map[string]adminuser{}
	maindata    = map[string]map[string]string{}
	userbooking = map[string]map[string][]string{}
)

func init() {
	//template setting
	tpl = template.Must(template.ParseGlob("templates/*"))
	var adm adminuser
	//read admin details
	file1, _ := ioutil.ReadFile("test.json")
	_ = json.Unmarshal([]byte(file1), &adm)
	jsonuser[adm.Username] = adm
	//read userdata details
	file2, _ := ioutil.ReadFile("userdata.json")
	_ = json.Unmarshal([]byte(file2), &userbooking)
	//setting userbooking
	if userbooking == nil {
		userbooking = make(map[string]map[string][]string)
	}
	//read maindata details
	file3, _ := ioutil.ReadFile("maindata.json")
	_ = json.Unmarshal([]byte(file3), &maindata)
	if maindata == nil {
		maindata = make(map[string]map[string]string)
	}
}

func main() {
	removepastdatetime()
	http.HandleFunc("/", index)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/booking", booking)
	http.HandleFunc("/view", view)
	http.HandleFunc("/change", change)
	http.HandleFunc("/admin", admin)
	http.HandleFunc("/appointment", appointment)
	http.HandleFunc("/block", block)
	http.HandleFunc("/delete", deleteAppt)
	http.HandleFunc("/session", session)
	http.HandleFunc("/user", deleteuser)
	http.HandleFunc("/deleteuser", deleteuser)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe("https://wkcjay.github.io/Dental-Appointment.github.io/", nil)

}
func removepastdatetime() {
	currenttime := time.Now()
	for k := range maindata {
		date, _ := time.Parse("2006-01-02", k)
		if date.Before(currenttime) {
			for time, username := range maindata[k] {
				remove(username, k, time)
			}
			delete(maindata, k)
		}
	}
	update()
}
func index(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if _, ok := jsonuser[myUser.Username]; ok {
		http.Redirect(res, req, "/admin", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "index.gohtml", myUser)
}

func signup(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	var myUser user
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		username := req.FormValue("username")
		password := req.FormValue("password")
		firstname := req.FormValue("firstname")
		lastname := req.FormValue("lastname")
		if username != "" {
			// check if username exist/ takentaken
			if _, exist := jsonuser[username]; exist {
				http.Error(res, "Username already", http.StatusForbidden)
				return
			}
			if _, ok := mapUsers[username]; ok {
				http.Error(res, "Username already taken", http.StatusForbidden)
				return
			}
			// create session
			cr8session(username, res)

			bPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				http.Error(res, "Internal server error", http.StatusInternalServerError)
				return
			}

			myUser = user{username, bPassword, firstname, lastname}
			mapUsers[username] = myUser
		}
		// redirect to main index
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return

	}
	tpl.ExecuteTemplate(res, "signup.gohtml", myUser)
}

func login(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	// process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		// check if user exist with username
		if alphauser, ok := jsonuser[username]; ok {
			err := bcrypt.CompareHashAndPassword(alphauser.Password, []byte(password))
			if err != nil {
				http.Error(res, "Username and/or Password do not match", http.StatusUnauthorized)
			}
			cr8session(username, res)
			http.Redirect(res, req, "/admin", http.StatusSeeOther)
			return
		}
		myUser, ok := mapUsers[username]
		if !ok {
			http.Error(res, "Username and/or password do not match", http.StatusUnauthorized)
			return
		}
		// Matching of password entered
		err := bcrypt.CompareHashAndPassword(myUser.Password, []byte(password))
		if err != nil {
			http.Error(res, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// create session
		cr8session(username, res)
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "login.gohtml", nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myCookie, _ := req.Cookie("myCookie")
	// delete the session
	delete(mapSessions, myCookie.Value)
	// remove the cookie
	myCookie = &http.Cookie{
		Name:   "myCookie",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(res, myCookie)
	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func booking(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	var username string
	username = myUser.Username
	timeslot := []string{"09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00", "17:00", "18:00"}
	Available := []string{}
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	if req.Method == http.MethodPost {
		time := req.FormValue("time")
		date := req.FormValue("date")
		//check available timeslot
		if date != "" {
			for i := 0; i < len(timeslot); i++ {
				if _, ok := maindata[date][timeslot[i]]; !ok {
					Available = append(Available, timeslot[i])
				}
			}
			prevdate = date
			tpl.ExecuteTemplate(res, "booking.gohtml", Available)
			return
		}
		if time != "" {
			date = prevdate
			if _, ok := userbooking[username]; !ok {
				userbooking[username] = make(map[string][]string)
			}
			if _, ok1 := userbooking[username][date]; !ok1 {
				userbooking[username][date] = make([]string, 0)
			}
			if _, ok2 := maindata[date]; !ok2 {
				maindata[date] = make(map[string]string)
			}
			userbooking[username][date] = append(userbooking[username][date], time)
			sort.Strings(userbooking[username][date])
			maindata[date][time] = username
			update()
			http.Redirect(res, req, "/view", http.StatusSeeOther)
			return
		}
	}
	tpl.ExecuteTemplate(res, "booking.gohtml", Available)
}

func view(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myUser := getUser(res, req)
	username := myUser.Username
	myUserBooking := userbooking[username]
	if req.Method == http.MethodPost {
		timeslot := req.FormValue("timeslot")
		datetime := strings.Split(timeslot, " ")
		date := datetime[0]
		time := datetime[1]
		delete(maindata[date], time)
		remove(username, date, time)
		update()
		tpl.ExecuteTemplate(res, "view.gohtml", myUserBooking)
		return
	}
	tpl.ExecuteTemplate(res, "view.gohtml", myUserBooking)
}

func change(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myUser := getUser(res, req)
	if req.Method == http.MethodPost {
		oldpassword := req.FormValue("oldpassword")
		newpassword := req.FormValue("newpassword")
		confirmpwd := req.FormValue("confirmpassword")
		err := bcrypt.CompareHashAndPassword(myUser.Password, []byte(oldpassword))
		if err != nil {
			http.Error(res, "Password do not match", http.StatusForbidden)
			return
		}
		if newpassword == "" || confirmpwd == "" {
			http.Error(res, "Empty Input", http.StatusForbidden)
			return
		}
		if newpassword != confirmpwd {
			http.Error(res, "Confirmed Password is different from new password", http.StatusForbidden)
			return
		}
		bPassword, err := bcrypt.GenerateFromPassword([]byte(confirmpwd), bcrypt.MinCost)
		if err != nil {
			http.Error(res, "Internal server error", http.StatusInternalServerError)
			return
		}
		myUser.Password = bPassword
		mapUsers[myUser.Username] = myUser
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return

	}
	tpl.ExecuteTemplate(res, "change.gohtml", myUser)
}

func admin(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !adminblocker(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "admin.gohtml", myUser)
}

func appointment(res http.ResponseWriter, req *http.Request) {
	if !adminblocker(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "appointment.gohtml", maindata)
}
func block(res http.ResponseWriter, req *http.Request) {
	if !adminblocker(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myUser := getUser(res, req)
	usern := myUser.Username
	if req.Method == http.MethodPost {
		var slot []string
		startdate := req.FormValue("startdate")
		enddate := req.FormValue("enddate")
		slots := req.FormValue("time")
		if startdate == "" || enddate == "" || slots == "" {
			http.Error(res, "Missing Input Value, Block Appointment Unsuccessful", http.StatusUnauthorized)
		}
		if slots == "am" {
			slot = []string{"09:00", "10:00", "11:00", "12:00"}
		} else if slots == "pm" {
			slot = []string{"13:00", "14:00", "15:00", "16:00", "17:00", "18:00"}
		} else {
			slot = []string{"09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00", "17:00", "18:00"}
		}
		layout := "2006-01-02"
		s, _ := time.Parse(layout, startdate)
		e, _ := time.Parse(layout, enddate)
		for e.After(s) {
			date := s.Format("2006-01-02")
			for i := 0; i < len(slot); i++ {
				username, taken := maindata[date][slot[i]]
				if taken {
					remove(username, date, slot[i])
				}
				if _, ok := userbooking[usern]; !ok {
					userbooking[usern] = make(map[string][]string)
				}
				if _, ok1 := userbooking[usern][date]; !ok1 {
					userbooking[usern][date] = make([]string, 0)
				}
				if _, ok2 := maindata[date]; !ok2 {
					maindata[date] = make(map[string]string)
				}
				maindata[date][slot[i]] = usern
				userbooking[usern][date] = append(userbooking[usern][date], slot[i])
				sort.Strings(userbooking[usern][date])
			}
			s = s.AddDate(0, 0, 1)
		}
		update()
		http.Redirect(res, req, "/appointment", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "block.gohtml", maindata)
}
func deleteAppt(res http.ResponseWriter, req *http.Request) {
	if !adminblocker(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		timeslot := req.FormValue("timeslot")
		datetime := strings.Split(timeslot, " ")
		date := datetime[0]
		time := datetime[1]
		username := maindata[date][time]
		delete(maindata[date], time)
		remove(username, date, time)
		update()
	}
	tpl.ExecuteTemplate(res, "delete.gohtml", maindata)
}
func session(res http.ResponseWriter, req *http.Request) {
	// myUser := getUser(res, req)
	if !adminblocker(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		cookval := req.FormValue("username")
		delete(mapSessions, cookval)
	}
	tpl.ExecuteTemplate(res, "session.gohtml", mapSessions)
}

func deleteuser(res http.ResponseWriter, req *http.Request) {
	if !adminblocker(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		delete(mapUsers, username)
		for cookval, usern := range mapSessions {
			if usern == username {
				delete(mapSessions, cookval)
			}
		}
		for date, timeslots := range userbooking[username] {
			for i := 0; i < len(timeslots); i++ {
				delete(maindata[date], timeslots[i])
			}
		}
		delete(userbooking, username)
	}
	update()
	tpl.ExecuteTemplate(res, "user.gohtml", mapUsers)
}

func getUser(res http.ResponseWriter, req *http.Request) user {
	// get current session cookie
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		id, _ := uuid.NewV4()
		myCookie = &http.Cookie{
			Name:  "myCookie",
			Value: id.String(),
		}

	}
	http.SetCookie(res, myCookie)

	// if the user exists already, get user
	var myUser user
	if username, ok := mapSessions[myCookie.Value]; ok {
		if alphauser, ok := jsonuser[username]; ok {
			return user(alphauser)
		} else {
			myUser = mapUsers[username]
			return myUser
		}
	}
	return myUser
}

func alreadyLoggedIn(req *http.Request) bool {
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		return false
	}
	username := mapSessions[myCookie.Value]
	if _, ok := mapUsers[username]; ok {
		return ok
	} else if _, ok := jsonuser[username]; ok {
		return ok
	} else {
		return ok
	}
}

func adminblocker(req *http.Request) bool {
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		return false
	}
	username := mapSessions[myCookie.Value]
	_, ok := jsonuser[username]
	return ok
}

func cr8session(username string, res http.ResponseWriter) {
	id, _ := uuid.NewV4()
	myCookie := &http.Cookie{
		Name:  "myCookie",
		Value: id.String(),
	}
	http.SetCookie(res, myCookie)
	mapSessions[myCookie.Value] = username
}

func remove(username string, date string, time string) {
	for i, v := range userbooking[username][date] {
		if v == time {
			userbooking[username][date] = append(userbooking[username][date][:i], userbooking[username][date][i+1:]...)
		}
	}
}

func update() {
	userbookingbyte, _ := json.MarshalIndent(userbooking, "", " ")
	ioutil.WriteFile("userdata.json", userbookingbyte, 0644)
	maindatabyte, _ := json.MarshalIndent(maindata, "", " ")
	ioutil.WriteFile("maindata.json", maindatabyte, 0644)
}
