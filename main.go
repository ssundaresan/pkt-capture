package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"syscall"
	"time"
)

type CaptureConf struct {
	TcpdumpBin string `json:"tcpdump_bin"`
	Interface  string `json:"interface"`
	OutDir     string `json:"out_dir"`
	CapSize    int    `json:"cap_size"`
	HTTPPort   int    `json:"http_port"`
	StartChan  chan string
	StopChan   chan bool
	DoneChan   chan error
}

func (conf *CaptureConf) InitCmd(name string) *exec.Cmd {
	if conf.TcpdumpBin == "" || conf.Interface == "" || name == "" {
		log.Fatal("bad conf")
	}
	if conf.CapSize == 0 {
		conf.CapSize = 100
	}
	return exec.Command(conf.TcpdumpBin, "-i", conf.Interface, "-w", conf.OutDir+"/"+name, "-s", fmt.Sprintf("%d", conf.CapSize))
}

func (conf *CaptureConf) HandleTasks() {
	var cmd *exec.Cmd
	for {
		select {
		case name := <-conf.StartChan:
			fmt.Printf("received start\n")
			cmd = conf.InitCmd(name)
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
				conf.DoneChan <- cmd.Wait()
			}()
			fmt.Printf("Started %#v \n", cmd.Process)
		case <-conf.StopChan:
			log.Printf("received stop")
			if cmd == nil || cmd.Process == nil {
				continue
			}
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				syscall.Kill(-pgid, 15)
			} else {
				fmt.Printf("Couldn't kill %#v\n", err)
			}
		case err := <-conf.DoneChan:
			log.Printf("Done")
			if err != nil {
				fmt.Printf("failed to die properly %#v\n", err)
			}
		}
	}
}

func (conf *CaptureConf) CaptureStop(w http.ResponseWriter, r *http.Request) {
	conf.StopChan <- true
}

func (conf *CaptureConf) CaptureFiles(w http.ResponseWriter, r *http.Request) {
	_, f := path.Split(r.URL.Path)
	if len(f) > 0 {
		fn := conf.OutDir + "/" + f
		http.ServeFile(w, r, fn)
		os.Remove(fn)
	}
}

func (conf *CaptureConf) CaptureStart(w http.ResponseWriter, r *http.Request) {
	fn := fmt.Sprintf("%x.pcap", time.Now().UnixNano())
	conf.StartChan <- fn
	fmt.Fprintf(w, fn)
}

func main() {
	conf := new(CaptureConf)

	confFile, err := ioutil.ReadFile("input.conf")
	if err != nil {
		log.Fatal("opening conf file: ", err.Error())
	}
	err = json.Unmarshal(confFile, &conf)
	fmt.Printf("Conf%#v\n", conf)

	conf.StopChan = make(chan bool, 1)
	conf.StartChan = make(chan string, 1)
	conf.DoneChan = make(chan error, 1)

	http.HandleFunc("/capture_start", conf.CaptureStart)
	http.HandleFunc("/capture_stop", conf.CaptureStop)
	http.HandleFunc("/capture_files/", conf.CaptureFiles)

	go conf.HandleTasks()
	log.Fatal(http.ListenAndServe("0.0.0.0:9000", nil))
}
