package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gocarina/gocsv"
)

type config struct {
	nmapFile    string
	masscanFile string
	outFile     string
}

type portscan struct {
	Hostname     string
	IPAddress    string
	Port         int
	Protocol     string
	Servicename  string
	Servicestate string
}

var (
	cfg   config
	ps    []portscan
	found bool
	chost string
)

func loadConfig() {
	nmapFile := flag.String("nmapFile", "nmap.csv", "Nmap scan file in CSV")
	masscanFile := flag.String("masscanFile", "masscan.list", "Masscan scan file in List format")
	outFile := flag.String("outFile", "results.csv", "Final output merged file")

	flag.Parse()

	cfg = config{
		nmapFile:    *nmapFile,
		masscanFile: *masscanFile,
		outFile:     *outFile,
	}

}

func exists(path string) (bool, int64, error) {
	fi, err := os.Stat(path)
	if err == nil {
		return true, fi.Size(), nil
	}
	if os.IsNotExist(err) {
		return false, int64(0), nil
	}
	return false, int64(0), err
}

func ensureFilePathExists(filepath string) error {
	value := false
	fsize := int64(0)

	for (value == false) || (fsize == int64(0)) {
		i, s, err := exists(filepath)
		if err != nil {
			log.Println("Failed to determine if the file exists or not..")
		}
		value = i
		fsize = s
	}

	log.Println("File exists:", value)
	log.Println("File size:", fsize)

	return nil
}

func loopnmapfile(nmapfile string) error {
	ns, err := os.Open(nmapfile)
	if err != nil {
		log.Printf("Couldn't open the NMAP Scan file: %v", err)
		return err
	}
	defer ns.Close()

	nsfScanner := bufio.NewScanner(ns)
	nsfScanner.Split(bufio.ScanLines) // splitting at each line
	nsfcount := 0

	for nsfScanner.Scan() {
		if nsfcount == 0 {
			nsfcount++ //don't need the first line, increment the counter
		} else {
			nsline := strings.Split(nsfScanner.Text(), ",")
			tp, err := strconv.Atoi(nsline[2])
			if err != nil {
				log.Printf("Couldn't convert port string to int: %v", err)
				return err
			}
			p := portscan{
				Hostname:     nsline[0],
				IPAddress:    nsline[1],
				Port:         tp,
				Protocol:     nsline[3],
				Servicename:  nsline[4],
				Servicestate: nsline[5],
			}
			ps = append(ps, p)
		}
	}

	return nil
}

func writeResultsToCsv(scanResults []portscan, outputFilePath string) error {
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		fmt.Printf("Couldn't create the output file: %v", err)
		return err
	}
	defer outputFile.Close()

	err = gocsv.MarshalFile(&scanResults, outputFile)
	if err != nil {
		fmt.Printf("Couldn't marshal the output file: %v", err)
		return err
	}
	return nil
}

func main() {

	loadConfig()

	err := ensureFilePathExists(cfg.nmapFile)
	if err != nil {
		log.Fatalf("Couldn't ensure whether the NMAP file exists or not: %v", err)
	}

	err = ensureFilePathExists(cfg.masscanFile)
	if err != nil {
		log.Fatalf("Couldn't ensure whether the Masscan file exists or not: %v", err)
	}

	err = loopnmapfile(cfg.nmapFile) // need to loop through the nmap scan file and create a new array of portscans from that so that we can just keep appending anything new to that list
	if err != nil {
		log.Fatalf("Couldn't loop the nmap scan file: ", err)
	}

	// need to do some sed magic on the masscan file to get a CSV from the Masscan generated list file. stored at /tmp/masscantemp.txt
	masscanCmd := exec.Command("sh", "-c", "sed '1d;$d' "+cfg.masscanFile+" | cut -d' ' -f1,2,3,4 | sed 's/ /,/g' | sort -u > /tmp/masscantemp.txt")
	var masscanOut, masscanStderr bytes.Buffer
	masscanCmd.Stdout = &masscanOut
	masscanCmd.Stderr = &masscanStderr
	err = masscanCmd.Run()
	if err != nil {
		log.Fatalf("Couldn't run the sed command for Masscan Scan file: ", err)
	}

	// now scanning the temp masscan file per line and splitting on , just like the nmap file. no need to skip the first line though
	ms, err := os.Open("/tmp/masscantemp.txt")
	if err != nil {
		log.Fatalf("Couldn't open the masscan temp file: %v", err)
	}
	defer ms.Close()

	msfScanner := bufio.NewScanner(ms)
	msfScanner.Split(bufio.ScanLines) // splitting at each line

	found = false

	// For each line in the masscan file, we need to loop over the entire nmap file and see if an entry already exists from before for that masscan line
	// If it does, we have found a duplicate and need to move onto the next line in the masscan file
	// If it does not, we have found a new record found by masscan, which we need to merge with the existing nmap file.

	for msfScanner.Scan() { //looping over each line of the masscan file
		fmt.Println("=======================================")
		msline := strings.Split(msfScanner.Text(), ",")
		fmt.Println(msline)

		mip := msline[3]
		mstate := msline[0]
		mport := msline[2]
		mprotocol := msline[1]

		nmapscanfile, err := os.Open(cfg.nmapFile)
		if err != nil {
			log.Fatalf("Couldn't open the NMAP Scan file: %v", err)
		}
		defer nmapscanfile.Close()

		nmapScanner := bufio.NewScanner(nmapscanfile)
		nmapScanner.Split(bufio.ScanLines) // splitting at each line
		ncount := 0

		for nmapScanner.Scan() { // for each line from the masscan file, looping over all lines of the nmap file to find a possible match

			chost = ""

			if ncount == 0 {
				ncount++ //don't need the first line, increment the counter
			} else {

				nsline := strings.Split(nmapScanner.Text(), ",")
				fmt.Println(nsline)

				nhost := nsline[0]
				nip := nsline[1]
				nport := nsline[2]
				nstate := nsline[5]
				nprotocol := nsline[3]

				if mip == nip && mstate == nstate && mport == nport && mprotocol == nprotocol {
					fmt.Println("exact match found..")
					found = true
					break // need to stop scanning any more lines from the nmap file
				} else {
					fmt.Println("match not found")
					found = false

					if mip == nip { // need to check if the IP is the same in this run so that domain could be copied over
						chost = nhost
					}

					continue // match not found so need to continue iterating through the rest of the lines in the nmap file
				}

			}
		}

		if found {
			continue // exact match found so need to move onto the next line in the masscan file
		} else {
			// not found in any of the rows of the nmap scan file so need to create an entry
			p, err := strconv.Atoi(mport)
			if err != nil {
				log.Fatalf("Couldn't convert masscan port from string to int: %v", err)
			}

			var h string

			if chost != "" {
				h = chost
			} else {
				h = "NA"
			}

			foo := portscan{
				Hostname:     h,
				IPAddress:    mip,
				Port:         p,
				Protocol:     mprotocol,
				Servicename:  "NA",
				Servicestate: mstate,
			}
			ps = append(ps, foo)
		}

		found = false // setting this back to false for the next line in the masscan file

	}

	// writing the ps to the outfile once everything is done
	err = writeResultsToCsv(ps, cfg.outFile)
	if err != nil {
		log.Fatalf("Couldn't write to the out file: %v", err)
	}

	fmt.Println("=======================================")
	fmt.Println("Results saved to: " + cfg.outFile)
}
