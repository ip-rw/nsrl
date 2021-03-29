package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/ip-rw/bloom"
	"github.com/malice-plugins/pkgs/utils"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
)

var (
	ErrorRate = "0.001"
	HashType  = "sha1"
)

const (
	// NSRL fields
	sha1         = 0
	md5          = 1
	crc32        = 2
	fileName     = 3
	fileSize     = 4
	productCode  = 5
	opSystemCode = 6
	specialCode  = 7
)

type Nsrl struct {
	Results ResultsData `json:"nsrl"`
}

// ResultsData json object
type ResultsData struct {
	Found    bool   `json:"found"`
	Hash     string `json:"hash"`
	MarkDown string `json:"markdown,omitempty" structs:"markdown,omitempty"`
	Filename string `json:"filename"`
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func lineCounter(r io.Reader) (uint64, error) {
	buf := make([]byte, 32*1024)
	var count uint64
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += uint64(bytes.Count(buf[:c], lineSep))

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}

func getNSRLFieldFromHashType() int {
	switch strings.ToLower(HashType) {
	case "sha1":
		return 0
	case "md5":
		return 1
	case "crc32":
		return 2
	case "filename":
		return 3
	case "filesize":
		return 4
	case "productcode":
		return 5
	case "opsystemcode":
		return 6
	case "specialcode":
		return 7
	default:
		log.Warn(fmt.Errorf("hash type %s not supported", HashType))
	}
	return -1
}

// build bloomfilter from NSRL database
func buildFilter(db string) {
	var err error
	nsrlField := getNSRLFieldFromHashType()

	// open NSRL database
	nsrlDB, err := os.Open(path.Join(db, "NSRLFile.txt"))
	assert(err)
	defer nsrlDB.Close()
	// count lines in NSRL database
	lines, err := lineCounter(nsrlDB)
	assert(err)
	log.Debugf("Number of lines in NSRLFile.txt: %d", lines)
	// write line count to file LINECOUNT
	buf := new(bytes.Buffer)
	assert(binary.Write(buf, binary.LittleEndian, lines))
	assert(ioutil.WriteFile(path.Join(db, "LINECOUNT"), buf.Bytes(), 0644))

	// Create new bloomfilter with size = number of lines in NSRL database
	erate, err := strconv.ParseFloat(ErrorRate, 64)
	assert(err)

	//filter := cuckoo.NewScalableCuckooFilter(uint(lines))
	filter := bloom.New(float64(lines), erate)

	// jump back to the begining of the file
	_, err = nsrlDB.Seek(0, io.SeekStart)
	assert(err)

	log.Debug("Loading NSRL database into bloomfilter")
	reader := csv.NewReader(nsrlDB)
	// strip off csv header
	_, _ = reader.Read()
	for {
		record, err := reader.Read()

		if err == io.EOF {
			break
		}
		assert(err)

		// log.Debug(record)
		filter.Add([]byte(record[nsrlField]))
	}

	bloomFile, err := os.Create(path.Join(db, "nsrl.bloom"))
	assert(err)
	defer bloomFile.Close()

	log.Debug("Writing bloomfilter to disk")
	bloomFile.Write(filter.Marshal())
	bloomFile.Close()
	assert(err)
}

// lookUp queries the NSRL bloomfilter for a hash
func load(db string) *bloom.Bloom {

	var lines uint64

	// read line count from file LINECOUNT
	lineCount, err := ioutil.ReadFile(path.Join(db, "LINECOUNT"))
	assert(err)
	buf := bytes.NewReader(lineCount)
	assert(binary.Read(buf, binary.LittleEndian, &lines))
	log.Debugf("Number of lines in NSRLFile.txt: %d", lines)

	f, err := os.Open(path.Join(db, "nsrl.bloom"))
	assert(err)
	filter := bloom.Unmarshal(f)
	return filter
}

func lookUp(filter *bloom.Bloom, hash []byte) ResultsData {
	nsrlResults := ResultsData{}
	// test of existance of hash in bloomfilter
	nsrlResults.Found = filter.Has(hash)
	return nsrlResults
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "nsrl"
	app.Usage = "NSRL lookup"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:  "db",
			Value: "db",
			Usage: "db path",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "build",
			Aliases: []string{"b"},
			Usage:   "Build bloomfilter from NSRL database",
			Action: func(c *cli.Context) error {
				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}

				buildFilter(c.GlobalString("db"))
				return nil
			},
		},
		{
			Name:      "lookup",
			Aliases:   []string{"l"},
			Usage:     "Query NSRL for hash",
			ArgsUsage: fmt.Sprintf("%s to query NSRL with", strings.ToUpper(HashType)),
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) error {
				scanner := bufio.NewScanner(os.Stdin)
				filter := load(c.GlobalString("db"))
				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}

				for scanner.Scan() {
					line := scanner.Bytes()
					var i int
					if i = bytes.IndexAny(line, "\t "); i < 1 {
						log.Warn(fmt.Errorf("please supply a valid %s hash and filename (%s)", strings.ToUpper(HashType), line))
						continue
					}

					path := bytes.TrimSpace(line[i:])
					hash := bytes.ToUpper(line[:i])

					res := lookUp(filter, hash)
					res.Hash = string(hash)
					res.Filename = string(path)
					nsrlJSON, err := json.Marshal(res)
					assert(err)
					fmt.Println(string(nsrlJSON))
				}
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	assert(err)
}
