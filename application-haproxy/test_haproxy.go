package main

import (
	"bytes"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func main() {
	go startListener()

	time.Sleep(time.Second)

	runTests()
}

func runTests() {
	url := "127.0.0.1"
	port := "3333"
	username := "opsview"
	password := "opsview"
	checks := []string{"bytes", "connect_time", "current_queue", "current_session", "denied_connection", "denied_request", "denied_response", "denied_session", "error_connection", "error_request", "error_response", "intercepted_requests", "queue_time", "request_rate", "request_time", "response_code", "session_rate", "warnings_redispatched", "warnings_retried"}
	warnings := []string{"0", "50000000000"}
	criticals := []string{"0", "50000000001"}



	for i := range checks {
		runHaproxy(checks[i], warnings[1], criticals[1], "OK", url, port, username, password)
		runHaproxy(checks[i], warnings[0], criticals[1], "WARNING", url, port, username, password)
		runHaproxy(checks[i], warnings[0], criticals[0], "CRITICAL", url, port, username, password)
	}

	runHaproxy("intercepted_requests", warnings[1], criticals[1], "Connect", "12323541", port, username, password)
	runHaproxy("intercepted_requests", warnings[1], criticals[1], "Connect", url, "123125425", username, password)
	runHaproxy("aisfioa", warnings[1], criticals[1], "No check found", url, port, username, password)
	runHaproxy("intercepted_requests", "gasdg", criticals[1], "invalid value", url, port, username, password)
	runHaproxy("intercepted_requests", warnings[1], "sdgsafg", "invalid value", url, port, username, password)
	runHaproxy("intercepted_requests", warnings[1], criticals[1], "Hostname", "", port, username, password)
	runHaproxy("intercepted_requests", warnings[1], criticals[1], "Port", url, "", username, password)
	runHaproxy("", warnings[1], criticals[1], "Mode", url, port, username, password)
	runHaproxy("intercepted_requests", warnings[1], criticals[1], "Username", url, port, "", password)
	runHaproxy("intercepted_requests", warnings[1], criticals[1], "Password", url, port, username, "")
}

func runHaproxy(check string, warning string, critical string, expected string, url string, port string, username string, password string) {
	cmd := exec.Command("go", "run", "check_haproxy.go", "-m", check, "-H", url, "-P", port, "-w", warning, "-c", critical, "-u", username, "-p", password)
	var actual bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &actual
	cmd.Stderr = &stderr

	cmd.Run()

	actualString := strings.TrimSpace(actual.String())
	valueToFind := regexp.MustCompile(expected)
	foundValue := valueToFind.FindString(actualString)

	if foundValue != "" {
		print("PASS " + actual.String() + "\n")
	} else {
		print("FAIL Expecting: " + expected + " Actual: " + actualString + "\n")
	}
}

func startListener() {
	print("Server start\n")
	http.HandleFunc("/", jsonSetup)
	http.ListenAndServe("127.0.0.1:3333", nil)
}

func jsonSetup(w http.ResponseWriter, r *http.Request) {
	js := `pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,agent_status,agent_code,agent_duration,check_desc,agent_desc,check_rise,check_fall,check_health,agent_rise,agent_fall,agent_health,addr,cookie,mode,algo,conn_rate,conn_rate_max,conn_tot,intercepted,dcon,dses,
stats,FRONTEND,,,2,2,2000,3,160,1092,0,0,0,,,,,OPEN,,,,,,,,,1,1,0,,,,0,2,0,2,,,,0,1,0,0,0,0,,1,1,2,,,0,0,0,0,,,,,,,,,,,,,,,,,,,,,http,,2,2,3,2,0,0,
stats,BACKEND,0,0,0,0,200,0,160,1092,0,0,,0,0,0,0,UP,0,0,0,,0,252,,,1,1,0,,0,,1,0,,0,,,,0,0,0,0,0,0,,,,0,0,0,0,0,0,0,0,,,0,0,0,0,,,,,,,,,,,,,,http,,,,,0,,,`

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(js))
}
