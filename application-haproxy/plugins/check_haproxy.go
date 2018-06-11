// Copyright (C) 2003-2018 Opsview Limited. All rights reserved
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	opspacks "github.com/webb249/ops/opspacks"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const FRONTEND = "0"

var USAGETEXT = `Check for HAProxy status

	Usage: "check_haproxy -m <CHECK> -H <HOSTADDRESS> -P <PORT> -u <USERNAME> -p <PASSWORD> -w <WARNING> -c <CRITICAL> -s <STATSPATH> -n <PROXYNAME>"

	-h, --help
		Print this help screen
	-m, -mode=MODE
		The HAProxy check to run, options are:
			status: Checks the status of each server
			bytes: Checks the bytes in and bytes out
			connect_time: The time in ms of the connect session
			current_queue: The current number in the queue
			session_used: Gets the perentage of used sessions
			denied_connection: The number of denied connections made to the system
			denied_request: The number of denied requests made to the system
			denied_response: The number of denied responses made to the system
			denied_sessions: The number of denied session made to the system
			error_connection: The number of error connections
			error_request: The number of error requests
			error_response: The number of error responses
			intercepted_requests: The number of intercepted requests
			queue_time: The time in ms of the queue session
			request_rate: The number of requests per second
			request_time: The time in ms of the session request
			response_code: The number of code responses of each type
			session_rate: The number of sessions per second
			warnings_redispatched: The number of redispatched warnings
			warnings_retried: The number of retried warnings
	-H, --hostname=HOSTADDRESS
		HostAddress prefix for API access. Required.
	-P, --port=PORT
		Port for API access. If not specified default port 1936 will be used.
	-u, --username=Username
		Username for access to the system. Required.
	-p, --password=Password
		Password for access to the system. Required.
	-w, --warning=INTEGER
		Warning level.
	-c, --critical=INTEGER
		Critical level.
	-s, --statspath=STRING
		Stats URI.
	-n, --proxyname=STRING
		Name of proxy to be monitored.
		`

func main() {
	var previousValues []map[string]string

	check := opspacks.NewCheck("Haproxy")
	defer check.Finish()

	HelpMenu := flag.Bool("h", false, "Help Menu")
	HostAddress := flag.String("H", "127.0.0.1", "Hostname")
	Port := flag.String("P", "", "Port")
	Mode := flag.String("m", "", "Mode")
	Username := flag.String("u", "", "Username")
	Password := flag.String("p", "", "Password")
	Warning := flag.Int("w", -1, "Warning")
	Critical := flag.Int("c", -1, "Critical")
	StatsPath := flag.String("s", "", "StatsPath")
	ProxyName := flag.String("n", "", "ProxyName")

	flag.Parse()

	if *HelpMenu == true {
		fmt.Println(USAGETEXT)
		os.Exit(int(opspacks.UNKNOWN))
	}
	flagCheck(*HostAddress, *Mode, *Username, *Password, *ProxyName, *Port)

	if *Port != "" {
		*Port = ":" + *Port
	}
	records, bodyText := fetch(*HostAddress, *Port, *Username, *Password, *StatsPath)

	switch *Mode {
	case "status":
		statusPerf(check, records, *ProxyName)
	case "session_used":
		sessionUsedPerf(check, records, *ProxyName, *Warning, *Critical)
	case "current_queue":
		findPerfLoop(records, previousValues, *ProxyName, "qcur", "Requests", check, *Warning, *Critical, "Current_Queue", false, false)
	case "bytes":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "bin", "b", check, *Warning, *Critical, "Bytes_In", true, true)
		findPerfLoop(records, previousValues, *ProxyName, "bout", "b", check, *Warning, *Critical, "Bytes_Out", true, true)
	case "denied_request":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "dreq", "Requests", check, *Warning, *Critical, "Denied_Request", true, true)
	case "denied_response":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "dresp", "Responses", check, *Warning, *Critical, "Denied_Response", false, true)
	case "error_request":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "ereq", "Errors", check, *Warning, *Critical, "Error_Request", true, true)
	case "error_connection":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "econ", "Errors", check, *Warning, *Critical, "Error_Connection", false, true)
	case "error_response":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "eresp", "Responses", check, *Warning, *Critical, "Error_Response", false, true)
	case "warnings_retried":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "wretr", "Retries", check, *Warning, *Critical, "Warnings_Retried", false, true)
	case "warnings_redispatched":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "wredis", "Redispatches", check, *Warning, *Critical, "Warnings_Redispatched", false, true)
	case "session_rate":
		findPerfLoop(records, previousValues, *ProxyName, "rate", "ps", check, *Warning, *Critical, "Session_Rate", true, false)
	case "response_code":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "hrsp_4xx", "Responses", check, *Warning, *Critical, "Code_4xx", true, true)
		findPerfLoop(records, previousValues, *ProxyName, "hrsp_5xx", "Responses", check, *Warning, *Critical, "Code_5xx", true, true)
		findPerfLoop(records, previousValues, *ProxyName, "hrsp_other", "Responses", check, *Warning, *Critical, "Code_Other", true, true)
		findPerfLoop(records, previousValues, *ProxyName, "hrsp_4xx", "Responses", check, *Warning, *Critical, "Code_4xx", false, true)
		findPerfLoop(records, previousValues, *ProxyName, "hrsp_5xx", "Responses", check, *Warning, *Critical, "Code_5xx", false, true)
		findPerfLoop(records, previousValues, *ProxyName, "hrsp_other", "Responses", check, *Warning, *Critical, "Code_Other", false, true)
	case "request_rate":
		findPerfLoop(records, previousValues, *ProxyName, "req_rate", "ps", check, *Warning, *Critical, "Request_Rate", true, false)
	case "queue_time":
		findPerfLoop(records, previousValues, *ProxyName, "qtime", "ms", check, *Warning, *Critical, "Queue_Time", false, false)
	case "connect_time":
		findPerfLoop(records, previousValues, *ProxyName, "ctime", "ms", check, *Warning, *Critical, "Connect_Time", false, false)
	case "request_time":
		findPerfLoop(records, previousValues, *ProxyName, "rtime", "ms", check, *Warning, *Critical, "Request_Time", false, false)
	case "intercepted_requests":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "intercepted", "Requests", check, *Warning, *Critical, "Intercepted_Requests", true, true)
	case "denied_connection":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "dcon", "Connections", check, *Warning, *Critical, "Denied_Connection", true, true)
	case "denied_session":
		previousValues = updateState(*HostAddress, *Port, *Mode, *ProxyName, bodyText)
		findPerfLoop(records, previousValues, *ProxyName, "dses", "Sessions", check, *Warning, *Critical, "Denied_Response", true, true)
	default:
		opspacks.Exit(opspacks.CRITICAL, "No check found")
	}
}

// Connect and retrieve the HaProxy csv file
func fetch(HostAddress string, Port string, Username string, Password string, StatsPath string) ([]map[string]string, string) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "http://"+HostAddress+Port+"/"+StatsPath+";csv", nil)
	opspacks.ExitAtError(err, "Cannot create connection request to "+HostAddress+":"+Port+"/"+StatsPath)

	if (Username != "") && (Password != "") {
		req.SetBasicAuth(Username, Password)
	}
	resp, err := client.Do(req)
	opspacks.ExitAtError(err, "Could Not Connect to "+HostAddress+Port+"/"+StatsPath)

	if resp.StatusCode != 200 {
		opspacks.Exit(opspacks.CRITICAL, "Could Not Connect to "+HostAddress+Port+"/"+StatsPath+" Response Code: "+string(resp.Status))
	}

	bodyText, err := ioutil.ReadAll(resp.Body)
	opspacks.ExitAtError(err, "Error reading output from "+HostAddress+Port+"/"+StatsPath)

	return decodeCsv(string(bodyText)), string(bodyText)
}

// Convert the csv string into an array for easier data manipulation
func decodeCsv(metrics string) []map[string]string {
	metrics = strings.Replace(metrics, "# ", "", 1)
	buf := bytes.NewBufferString(metrics)
	records := make([]map[string]string, 0)

	if len(metrics) > 0 {
		csvReader := csv.NewReader(buf)
		csvReader.TrimLeadingSpace = true
		recordNames, err := csvReader.Read()
		opspacks.ExitAtErrorPrint(err, "Error decoding CSV")

		for {
			record, err := csvReader.Read()
			if err == io.EOF {
				break
			} else {
				opspacks.ExitAtErrorPrint(err, "Error decoding CSV")
			}
			recordRow := make(map[string]string)
			for i, n := range recordNames {
				recordRow[n] = record[i]
			}
			records = append(records, recordRow)
		}
	}
	return records
}

// Evaulates the results of the status of each proxy and adds the result
func statusPerf(check *opspacks.Check, records []map[string]string, ProxyName string) {
	proxyFound := false
	returnStatus := opspacks.UNKNOWN

	for _, record := range records {
		if record["pxname"] == ProxyName {
			proxyFound = true
			if (record["status"] != "status") && (record["status"] != "") {
				status := record["status"]

				if (status == "UP") || (status == "OPEN") {
					returnStatus = opspacks.OK
				} else if status == "DOWN" {
					returnStatus = opspacks.CRITICAL
				} else if status == "no check" {
					returnStatus = opspacks.UNKNOWN
				}
				check.AddResult(returnStatus, record["svname"]+" Status: "+status)
			}
		}
	}
	if proxyFound == false {
		opspacks.Exit(opspacks.CRITICAL, "Unknown proxy requested: "+ProxyName)
	}
}

// Evaulates the results of the used sessions of each proxy and adds the result and perf data
func sessionUsedPerf(check *opspacks.Check, records []map[string]string, ProxyName string, Warning int, Critical int) {
	proxyFound := false
	for _, record := range records {
		if record["pxname"] == ProxyName {
			proxyFound = true
			if (record["scur"] != "") && (record["slim"] != "") {
				current, err := strconv.Atoi(record["scur"])
				opspacks.ExitAtError(err, "Error converting current "+record["scur"]+" to integer")

				limit, err := strconv.Atoi(record["slim"])
				opspacks.ExitAtError(err, "Error converting limit "+record["slim"]+" to integer")

				value := opspacks.GetPercentOf(current, limit)
				returnStatus := opspacks.Evaluate(Warning, Critical, value, false)
				returnValue := strconv.Itoa(value)

				check.AddPerfData(record["svname"]+"_"+"Session_Used", "%", float64(value))
				check.AddResult(returnStatus, record["svname"]+" Session_Used: "+returnValue)
			}
		}
	}
	if proxyFound == false {
		opspacks.Exit(opspacks.CRITICAL, "Unable to find proxy: "+ProxyName)
	}
}

// Loops through the records to find the values the service check has called for
func findPerfLoop(records []map[string]string, previousValues []map[string]string, ProxyName string, searchName string, UOM string, check *opspacks.Check, Warning int, Critical int, name string, frontend bool, getRate bool) {
	proxyFound := false
	metricsFound := false

	for lineNumber, record := range records {
		if record["pxname"] == ProxyName {
			proxyFound = true
			if frontend == true {
				if record["type"] == FRONTEND {
					metricsFound = true
					if getRate == true && len(previousValues) != 0 {
						findPerf(record, record[searchName], previousValues[lineNumber][searchName], UOM, check, Warning, Critical, name, getRate)
					} else {
						findPerf(record, record[searchName], "", UOM, check, Warning, Critical, name, getRate)
					}
				}
			} else {
				if record["type"] != FRONTEND {
					metricsFound = true
					if getRate == true && len(previousValues) != 0 {
						findPerf(record, record[searchName], previousValues[lineNumber][searchName], UOM, check, Warning, Critical, name, getRate)
					} else {
						findPerf(record, record[searchName], "", UOM, check, Warning, Critical, name, getRate)
					}
				}
			}
		}
	}
	if proxyFound == false {
		opspacks.Exit(opspacks.CRITICAL, "Unable to find proxy: "+ProxyName)
	}
	if metricsFound == false {
		opspacks.Exit(opspacks.CRITICAL, "Unable to find correct metrics under proxy: "+ProxyName)
	}
}

// Gets the value, then evaulates it and returns the data
func findPerf(records map[string]string, record string, previousValue string, UOM string, check *opspacks.Check, Warning int, Critical int, name string, getRate bool) {
	returnStatus := opspacks.OK
	value, err := strconv.Atoi(record)
	if err == nil {
		if getRate == true {
			if previousValue != "" {
				previousValue, err := strconv.Atoi(previousValue)
				if err == nil {
					value = value - previousValue
					returnStatus = opspacks.Evaluate(Warning, Critical, value, false)
					check.AddPerfData(records["svname"]+"_"+name, UOM, float64(value))
				}
			}
		} else {
			returnStatus = opspacks.Evaluate(Warning, Critical, value, false)
			check.AddPerfData(records["svname"]+"_"+name, UOM, float64(value))
		}
	}
	if record == "" {
		opspacks.Exit(opspacks.CRITICAL, "Error metrics are only available from haproxy 1.7")
	}
	check.AddResult(returnStatus, records["svname"]+" "+name+" : "+record)
}

// Everything that involves the file is run here
// Opens the file a so it can be read, then writes a new file with the current records
func updateState(HostAddress string, Port string, Mode string, ProxyName string, records string) []map[string]string {
	path := checkFilePath(HostAddress, Port, Mode, ProxyName)

	file, err := os.OpenFile(path, syscall.O_RDWR|syscall.O_CREAT, 0666)
	opspacks.ExitAtError(err, "Error creating temporary file: "+path)

	defer file.Close()
	getLock(file, path)
	defer releaseLock(file)

	fileBytes, err := ioutil.ReadFile(path)
	opspacks.ExitAtError(err, "Cannot read previous metrics from temporary file: "+path)

	previousValues := decodeCsv(string(fileBytes))

	file.Truncate(0)

	w := bufio.NewWriter(file)
	_, err = w.WriteString(records)
	opspacks.ExitAtError(err, "Error writing to temporary file: "+path)

	w.Flush()

	return previousValues
}

// Set the flock on the file so no other processes can read or write to it
func getLock(file *os.File, path string) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	if err != nil {
		opspacks.Exit(opspacks.OK, "Error locking temporary file: "+path)
	}
}

// Release file lock
func releaseLock(file *os.File) {
	syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

// Tests the locations of the path to check the file can be written
// Creates a file name using md5 to create a hash
func checkFilePath(HostAddress string, Port string, Mode string, ProxyName string) string {
	fileName := "haproxy_"
	hash := HostAddress + "," + Port + "," + Mode + "," + ProxyName

	digest := make([]byte, len(hash))
	copy(digest[:], hash)
	hash = fmt.Sprintf("%x", md5.Sum(digest))
	fileName = fileName + string(hash[:]) + ".tmp"

	env := os.Getenv("OPSVIEW_BASE")

	path := env + "/tmp/" + fileName
	_, err := os.OpenFile(path, os.O_RDONLY, 0666)

	path = "/usr/local/nagios/tmp/" + fileName
	_, err1 := os.OpenFile(path, os.O_RDONLY, 0666)

	if !os.IsPermission(err) {
		path = env + "/tmp/" + fileName
	} else if !os.IsPermission(err1) {
		path = "/usr/local/nagios/tmp/" + fileName
	} else {
		path = "/tmp/" + fileName
		_, err = os.OpenFile(path, os.O_RDONLY, 0666)
		if os.IsPermission(err) {
			opspacks.Exit(opspacks.CRITICAL, "Error creating temp file unable to access "+path)
		}
	}
	return path
}

// Checks the required flags
func flagCheck(HostAddress string, Mode string, Username string, Password string, ProxyName string, PortValue string) {
	if HostAddress == "" {
		err := errors.New("Flag check error")
		opspacks.ExitAtError(err, "Hostname (-H) is a required argument")
	}
	if Mode == "" {
		err := errors.New("Flag check error")
		opspacks.ExitAtError(err, "Check (-m) is a required argument")
	}
	if ProxyName == "" {
		err := errors.New("Flag check error")
		opspacks.ExitAtError(err, "Proxy Name (-n) is a required argument")
	}
	Port, _ := strconv.Atoi(PortValue)
	if (PortValue != "") && ((Port < 1) || (Port > 65535)) {
		err := errors.New("Port check error")
		opspacks.ExitAtError(err, "Port must be between 1 and 65535")
	}
}
