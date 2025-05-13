package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

var (
	serverAddr = flag.String("addr", "http://localhost:8080", "DSDE server address")
)

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func upload(user, path string) {
	f, err := os.Open(path)
	must(err)
	defer f.Close()

	req, err := http.NewRequest("POST", *serverAddr+"/files", f)
	must(err)
	req.Header.Set("X-Owner-ID", user)
	req.Header.Set("X-Filename", filepath.Base(path))

	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "upload failed (%d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	var out map[string]string
	must(json.NewDecoder(resp.Body).Decode(&out))
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
}

func download(user, fileID, outpath string) {
	req, err := http.NewRequest("GET", *serverAddr+"/files/"+fileID, nil)
	must(err)
	req.Header.Set("X-Owner-ID", user)

	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "download failed (%d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	outF, err := os.Create(outpath)
	must(err)
	defer outF.Close()

	_, err = io.Copy(outF, resp.Body)
	must(err)
	fmt.Println("wrote", outpath)
}

func s3List() {
	resp, err := http.Get(*serverAddr + "/admin/s3-list")
	must(err)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "s3-list failed (%d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	var keys []string
	must(json.NewDecoder(resp.Body).Decode(&keys))
	for _, k := range keys {
		fmt.Println(k)
	}
}

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: client <upload|download|s3-list> [args]\n")
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "upload":
		if flag.NArg() != 3 {
			fmt.Fprintf(os.Stderr, "usage: client upload <user> <filepath>\n")
			os.Exit(1)
		}
		upload(flag.Arg(1), flag.Arg(2))

	case "download":
		if flag.NArg() != 4 {
			fmt.Fprintf(os.Stderr, "usage: client download <user> <fileID> <outpath>\n")
			os.Exit(1)
		}
		download(flag.Arg(1), flag.Arg(2), flag.Arg(3))

	case "s3-list":
		s3List()

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(1)
	}
}
