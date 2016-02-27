package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"syscall"
	"time"
)

var stopChan = make(chan bool, 1)
var startChan = make(chan string, 1)
var done = make(chan error, 1)
var pcapDir = "/tmp/pcapDir"

func InitCmd(name string) *exec.Cmd {
	return exec.Command("/opt/local/sbin/tcpdump", "-i", "en0", "-w", pcapDir+"/"+name, "-s", "100")
}

func HandleTasks() {
	var cmd *exec.Cmd
	for {
		select {
		case name := <-startChan:
			fmt.Printf("received start\n")
			cmd = InitCmd(name)
			if cmd.Process != nil {
				fmt.Printf("Already running\n")
				continue
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			err := cmd.Start()
			if err != nil {
				log.Fatal("failed to start")
			}
			go func() {
				done <- cmd.Wait()
			}()
			fmt.Printf("%#v \n", cmd.Process)
		case <-stopChan:
			log.Printf("received stop")
			if cmd == nil || cmd.Process == nil {
				continue
			}
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				syscall.Kill(-pgid, 15)
			} else {
				fmt.Printf("Couldn't kill %#v\n", err)
			}
		case err := <-done:
			log.Printf("Done")
			if err != nil {
				fmt.Printf("failed to die properly %#v\n", err)
			}
		}
	}
}

func CaptureStop(w http.ResponseWriter, r *http.Request) {
	stopChan <- true
}

func CaptureFiles(w http.ResponseWriter, r *http.Request) {
	_, f := path.Split(r.URL.Path)
	if len(f) > 0 {
		fn := pcapDir + "/" + f
		http.ServeFile(w, r, fn)
		os.Remove(fn)
	}
}

func CaptureStart(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("get %#v", r.Body)
	fn := fmt.Sprintf("%x.pcap", time.Now().UnixNano())
	startChan <- fn
	fmt.Fprintf(w, fn)
}

func main() {
	stopChan = make(chan bool, 1)
	http.HandleFunc("/capture_start", CaptureStart)
	http.HandleFunc("/capture_stop", CaptureStop)
	http.HandleFunc("/capture_files/", CaptureFiles)

	go HandleTasks()
	log.Fatal(http.ListenAndServe("0.0.0.0:9000", nil))
}
