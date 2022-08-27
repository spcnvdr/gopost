// fdata is responsible for getting information about the files in a directory
package fdata

import (
	"log"
	"math"
	"os"
	"strconv"
	"time"
)

/*
File: a small struct to hold information about a file that can be easily
displayed in templates
*/
type File struct {
	Name  string
	Size  string
	Mode  string
	Date  string
	IsDir bool
}

/*
	Files is a slice holding information about each file in the destination

directory
*/
type Files []File

// sizeToStr converts a file size in bytes to a human friendy string.
func SizeToStr(n int64) string {
	if n == 0 {
		return "0B"
	}

	b := float64(n)
	units := []string{"B", "K", "M", "G", "T", "P", "E"}

	i := math.Floor(math.Log(b) / math.Log(1024))
	return strconv.FormatFloat((b/math.Pow(1024, i))*1, 'f', 1, 64) + units[int(i)]
}

/*
fileFunc is called on each file in the target directory and returns
a Files struct with the relevant information about each file.
*/
func FileFunc(path string) (Files, error) {
	var fs Files

	files, err := os.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		var f File

		finfo, err := file.Info()
		if err != nil {
			continue
		}

		f.Name = finfo.Name()
		f.Size = SizeToStr(finfo.Size())
		f.Mode = finfo.Mode().String()
		f.Date = finfo.ModTime().Format(time.UnixDate)
		f.IsDir = finfo.IsDir()
		fs = append(fs, f)
	}
	return fs, nil
}
