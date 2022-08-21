package files

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"os"
)

/* File Functions */

/*
createFile helper function to create a new file and return the file descriptor
*/
func CreateFile(name string) *os.File {
	f, err := os.Create(name)
	if err != nil {
		log.Fatalf("Failed to created file: %v", err)
	}
	return f
}

// closeFile will close an open file, bails on error
func CloseFile(f *os.File) {
	err := f.Close()
	if err != nil {
		log.Fatalf("Error closing file: %v", err)
	}
}

// statFile calls os.Stat on a given path
func StatFile(path string) fs.FileInfo {
	info, err := os.Stat(path)
	if err != nil {
		log.Fatalf("Error os.Stat() %s: %v", path, err)
	}
	return info
}

// checkDir ensures we can access the given path and it is a directory.
func CheckDir(path string) error {
	info := StatFile(path)
	if !info.IsDir() {
		return fmt.Errorf("error: not a directory %s", path)
	}

	return nil
}

// exists checks if file/folder exists
func Exists(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

/*
CopyUploadFile copies a multipart form file to the file system
returns an error so we can return a 500 instead of crashing/exiting
*/
func CopyUploadFile(path string, src multipart.File) error {
	dst, err := os.Create(path)
	if err != nil {
		return err
	}

	defer dst.Close()
	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}
	return err
}
