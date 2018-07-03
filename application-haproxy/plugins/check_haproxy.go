package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"errors"
	opspacks "github.com/opsview/go-plugin"
)

const FRONTEND = "0"

var opts struct {
	HostAddress string `short:"H" long:"hostname" description:"Host" default:"localhost"`
	Port        string `short:"P" long:"port" description:"Port" default:"9000"`
	Mode        string `short:"m" long:"mode" description:"Mode" required:"true"`
	Warning     string `short:"w" long:"warning" description:"Warning"`
	Critical    string `short:"c" long:"critical" description:"Critical"`
	Username    string `short:"u" long:"Username" description:"proxy auth username"`
	Password    string `short:"p" long:"Password" description:"proxy auth password"`
	StatsPath   string `short:"s" long:"StatsPath" description:"Path the plugin uses to get metrics" required:"true"`
	ProxyName   string `short:"n" long:"ProxyName" description:"Proxy name set in configuration file" required:"true"`
}

func main() {
	var previousValues []map[string]string

	check := checkPlugin()
	if err := check.ParseArgs(&opts); err != nil {
		check.ExitCritical("Error parsing arguments: %s", err)
	}
	defer check.Final()
	check.AllMetricsInOutput = true

	if opts.Port != "" {
		opts.Port = ":" + opts.Port
	}
	records, bodyText := fetch(check, opts.HostAddress, opts.Port, opts.Username, opts.Password, opts.StatsPath)

	switch opts.Mode {
	case "status":
		statusPerf(check, records, opts.ProxyName)
	case "session_used":
		sessionUsedPerf(check, records, opts.ProxyName, opts.Warning, opts.Critical)
	case "current_queue":
		findPerfLoop(records, previousValues, opts.ProxyName, "qcur", "Requests", check, opts.Warning, opts.Critical, "Current_Queue", false, false, true)
	case "bytes":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "bin", "b", check, opts.Warning, opts.Critical, "Bytes_In", true, true, true)
		findPerfLoop(records, previousValues, opts.ProxyName, "bout", "b", check, opts.Warning, opts.Critical, "Bytes_Out", true, true, true)
	case "denied_request":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "dreq", "Requests", check, opts.Warning, opts.Critical, "Denied_Request", true, true, true)
	case "denied_response":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "dresp", "Responses", check, opts.Warning, opts.Critical, "Denied_Response", false, true, true)
	case "error_request":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "ereq", "Errors", check, opts.Warning, opts.Critical, "Error_Request", true, true, true)
	case "error_connection":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "econ", "Errors", check, opts.Warning, opts.Critical, "Error_Connection", false, true, true)
	case "error_response":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "eresp", "Responses", check, opts.Warning, opts.Critical, "Error_Response", false, true, true)
	case "warnings_retried":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "wretr", "Retries", check, opts.Warning, opts.Critical, "Warnings_Retried", false, true, true)
	case "warnings_redispatched":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "wredis", "Redispatches", check, opts.Warning, opts.Critical, "Warnings_Redispatched", false, true, true)
	case "session_rate":
		findPerfLoop(records, previousValues, opts.ProxyName, "rate", "/s", check, opts.Warning, opts.Critical, "Session_Rate", true, false, true)
	case "response_code":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "hrsp_4xx", "Responses", check, opts.Warning, opts.Critical, "Code_4xx", true, true, true)
		findPerfLoop(records, previousValues, opts.ProxyName, "hrsp_5xx", "Responses", check, opts.Warning, opts.Critical, "Code_5xx", true, true, true)
		findPerfLoop(records, previousValues, opts.ProxyName, "hrsp_other", "Responses", check, opts.Warning, opts.Critical, "Code_Other", true, true, true)
		findPerfLoop(records, previousValues, opts.ProxyName, "hrsp_4xx", "Responses", check, opts.Warning, opts.Critical, "Code_4xx", false, true, true)
		findPerfLoop(records, previousValues, opts.ProxyName, "hrsp_5xx", "Responses", check, opts.Warning, opts.Critical, "Code_5xx", false, true, true)
		findPerfLoop(records, previousValues, opts.ProxyName, "hrsp_other", "Responses", check, opts.Warning, opts.Critical, "Code_Other", false, true, true)
	case "request_rate":
		findPerfLoop(records, previousValues, opts.ProxyName, "req_rate", "/s", check, opts.Warning, opts.Critical, "Request_Rate", true, false, true)
	case "queue_time":
		findPerfLoop(records, previousValues, opts.ProxyName, "qtime", "ms", check, opts.Warning, opts.Critical, "Queue_Time", false, false, true)
	case "connect_time":
		findPerfLoop(records, previousValues, opts.ProxyName, "ctime", "ms", check, opts.Warning, opts.Critical, "Connect_Time", false, false, true)
	case "request_time":
		findPerfLoop(records, previousValues, opts.ProxyName, "rtime", "ms", check, opts.Warning, opts.Critical, "Request_Time", false, false, true)
	case "intercepted_requests":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "intercepted", "Requests", check, opts.Warning, opts.Critical, "Intercepted_Requests", true, true, true)
	case "denied_connection":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "dcon", "Connections", check, opts.Warning, opts.Critical, "Denied_Connection", true, true, true)
	case "denied_session":
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "dses", "Sessions", check, opts.Warning, opts.Critical, "Denied_Response", true, true, true)
	case "summary_stats":
		//status
		statusPerf(check, records, opts.ProxyName)
		//Bytes in and out
		previousValues = updateState(check, opts.HostAddress, opts.Port, opts.Mode, opts.ProxyName, bodyText)
		findPerfLoop(records, previousValues, opts.ProxyName, "bin", "b", check, "", "", "Bytes_In", true, true, true)
		findPerfLoop(records, previousValues, opts.ProxyName, "bout", "b", check, "", "", "Bytes_Out", true, true, true)
		//current queue
		findPerfLoop(records, previousValues, opts.ProxyName, "qcur", "Requests", check, "", "", "Current_Queue", false, false, false)
		//request rate
		findPerfLoop(records, previousValues, opts.ProxyName, "req_rate", "/s", check, "", "", "Request_Rate", true, false, false)
		//session rate
		findPerfLoop(records, previousValues, opts.ProxyName, "rate", "/s", check, "", "", "Session_Rate", true, false, false)
	default:
		check.ExitUnknown("Not a valid mode, please check mode flag")
	}
}

// Connect and retrieve the HaProxy csv file
func fetch(check *opspacks.Plugin, HostAddress string, Port string, Username string, Password string, StatsPath string) ([]map[string]string, string) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "http://"+HostAddress+Port+"/"+StatsPath+";csv", nil)
	if err != nil {
		check.ExitUnknown("Cannot create connection request to "+HostAddress+":"+Port+"/"+StatsPath+" %s", err)
	}
	if (Username != "") && (Password != "") {
		req.SetBasicAuth(Username, Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		check.ExitUnknown("Could Not Connect to " + HostAddress + Port + "/" + StatsPath)
	}
	if resp.StatusCode != 200 {
		check.ExitUnknown("Could Not Connect to " + HostAddress + Port + "/" + StatsPath + " Response Code: " + string(resp.Status))
	}

	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		check.ExitUnknown("Error reading output from " + HostAddress + Port + "/" + StatsPath)
	}
	return decodeCsv(check, string(bodyText)), string(bodyText)
}

// Convert the csv string into an array for easier data manipulation
func decodeCsv(check *opspacks.Plugin, metrics string) []map[string]string {
	metrics = strings.Replace(metrics, "# ", "", 1)
	buf := bytes.NewBufferString(metrics)
	records := make([]map[string]string, 0)

	if len(metrics) > 0 {
		csvReader := csv.NewReader(buf)
		csvReader.TrimLeadingSpace = true
		recordNames, err := csvReader.Read()
		if err != nil {
			check.ExitUnknown("Error decoding CSV")
		}
		for {
			record, err := csvReader.Read()
			if err == io.EOF {
				break
			} else if err != nil {
				check.ExitUnknown("Error decoding CSV")
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
func statusPerf(check *opspacks.Plugin, records []map[string]string, ProxyName string) {
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
				check.AddResult(returnStatus, record["svname"]+" Status is "+status)
			}
		}
	}
	if proxyFound == false {
		check.ExitUnknown("Unknown proxy requested: " + ProxyName)
	}
}

//Evaulates the results of the used sessions of each proxy and adds the result and perf data
func sessionUsedPerf(check *opspacks.Plugin, records []map[string]string, ProxyName string, Warning string, Critical string) {
	proxyFound := false
	for _, record := range records {
		if record["pxname"] == ProxyName {
			proxyFound = true
			if (record["scur"] != "") && (record["slim"] != "") {
				current, err := strconv.Atoi(record["scur"])
				if err != nil {
					check.ExitUnknown("Error converting current " + record["scur"] + " to integer")
				}
				limit, err := strconv.Atoi(record["slim"])
				if err != nil {
					check.ExitUnknown("Error converting limit " + record["slim"] + " to integer")
				}
				value := GetPercentOf(current, limit)
				check.AddMetric(record["svname"]+"_"+"Session_Used", value, "%", Warning, Critical)
			}
		}
	}
	if proxyFound == false {
		check.ExitUnknown("Unable to find proxy: " + ProxyName)
	}
}

// Loops through the records to find the values the service check has called for
func findPerfLoop(records []map[string]string, previousValues []map[string]string, ProxyName string, searchName string, UOM string, check *opspacks.Plugin, Warning string, Critical string, name string, frontend bool, getRate bool, evaluate bool) {
	proxyFound := false
	metricsFound := false

	for lineNumber, record := range records {
		if record["pxname"] == ProxyName {
			proxyFound = true
			if frontend == true {
				if record["type"] == FRONTEND {
					metricsFound = true
					if getRate == true && len(previousValues) != 0 {
						findPerf(record, record[searchName], previousValues[lineNumber][searchName], UOM, check, Warning, Critical, name, getRate, evaluate)
					} else {
						findPerf(record, record[searchName], "", UOM, check, Warning, Critical, name, getRate, evaluate)
					}
				}
			} else {
				if record["type"] != FRONTEND {
					metricsFound = true
					if getRate == true && len(previousValues) != 0 {
						findPerf(record, record[searchName], previousValues[lineNumber][searchName], UOM, check, Warning, Critical, name, getRate, evaluate)
					} else {
						findPerf(record, record[searchName], "", UOM, check, Warning, Critical, name, getRate, evaluate)
					}
				}
			}
		}
	}
	if proxyFound == false {
		check.ExitUnknown("Unable to find proxy: " + ProxyName)
	}
	if metricsFound == false {
		check.ExitUnknown("Unable to find correct metrics under proxy: " + ProxyName)
	}
}

// Gets the value, then evaulates it and returns the data
func findPerf(records map[string]string, record string, previousValue string, UOM string, check *opspacks.Plugin, Warning string, Critical string, name string, getRate bool, evaluate bool) {
	value, err := strconv.Atoi(record)
	if err == nil {
		if getRate == true {
			if previousValue != "" {
				previousValue, err := strconv.Atoi(previousValue)
				if err == nil {
					value = value - previousValue
					if evaluate == false {
						value1 := strconv.Itoa(value)
						check.AddResult(opspacks.OK, records["svname"]+"_"+name+" is "+value1+UOM)
					} else {
						check.AddMetric(records["svname"]+"_"+name, float64(value), UOM, Warning, Critical)
					}
				}
			}
		} else {
			if evaluate == false {
				value1 := strconv.Itoa(value)
				check.AddResult(opspacks.OK, records["svname"]+"_"+name+" is "+value1+UOM)
			} else {
				check.AddMetric(records["svname"]+"_"+name, float64(value), UOM, Warning, Critical)
			}
		}

	}
	if record == "" {
		check.ExitUnknown("Error metrics are only available from haproxy 1.7")
	}
}

// Everything that involves the file is run here
// Opens the file a so it can be read, then writes a new file with the current records
func updateState(check *opspacks.Plugin, HostAddress string, Port string, Mode string, ProxyName string, records string) []map[string]string {
	path, err := checkFilePath(HostAddress, Port, Mode, ProxyName)
	file, err := os.OpenFile(path, syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil {
		check.ExitUnknown("Error creating temporary file: " + path)
	}
	defer file.Close()
	getLock(check, file, path)
	defer releaseLock(file)

	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		check.ExitUnknown("Cannot read previous metrics from temporary file: "+path+" %s", err)
	}
	previousValues := decodeCsv(check, string(fileBytes))

	file.Truncate(0)

	w := bufio.NewWriter(file)
	_, err = w.WriteString(records)
	if err != nil {
		check.ExitUnknown("Error writing to temporary file: "+path+" %s", err)
	}
	w.Flush()

	return previousValues
}

// Set the flock on the file so no other processes can read or write to it
func getLock(check *opspacks.Plugin, file *os.File, path string) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	if err != nil {
		check.ExitUnknown("Error locking temporary file: "+path+" %s", err)
	}
}

// Release file lock
func releaseLock(file *os.File) {
	syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

func checkFilePath(HostAddress string, Port string, Mode string, ProxyName string) (string, error) {
	// Tests the locations of the path to check the file can be written
	// Creates a file name using md5 to create a hash
	// Returns a string of the path for the file to be written to

	fileName := "haproxy_"
	hash := HostAddress + "," + Port + "," + Mode + "," + ProxyName

	digest := make([]byte, len(hash))
	copy(digest[:], hash)
	hash = fmt.Sprintf("%x", md5.Sum(digest))
	fileName = fileName + string(hash[:]) + ".tmp"

	env := os.Getenv("OPSVIEW_BASE")

	paths := []string{"/opt/opsview/agent/tmp/",
		"/opt/opsview/monitoringscripts/tmp/",
		env + "/tmp/",
		"/tmp/"}

	var failedPaths string

	for _, path := range paths {
		// For all paths we can use for temp files

		if _, err := os.Stat(path); err == nil {
			// If temp path exists and user has permissions to read and write, return this path and filename
			return path + fileName, err
		} else {
			failedPaths += path + " or "
		}
	}

	// Return error if none of the paths available are valid
	err := errors.New("Unable to create temporary file in path(s): " + failedPaths[:len(failedPaths)-4])

	return "", err
}

func checkPlugin() *opspacks.Plugin {
	check := opspacks.New("check_haproxy", "v2.0.0")
	check.Preamble = `Copyright (C) 2003-2018 Opsview Limited. All rights reserved.
This plugin tests the stats of haproxy.`
	check.Description = `Check for HAProxy status

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
			summary_stats: Provides status of each server, the number of bytes in and out, the current number in queue, number of requests per second and the number of sessions per second
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
		Name of proxy to be monitored.`
	return check
}

func GetPercentOf(used int, total int) int {
	floatValue := (float64(used) / float64(total)) * float64(100)
	return int(floatValue)
}
