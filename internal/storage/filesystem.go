package storage

import (
	"io"
	"os"
	"path/filepath"
)

type StorageService struct {
	BasePath string
}

func NewFilesystem(basePath string) *StorageService {
	return &StorageService{
		BasePath: basePath,
	}
}

func (s *StorageService) Save(file io.Reader, sha256Hash string) (string, error) {
	if err := os.MkdirAll(s.BasePath, 0755); err != nil {
		return "", err
	}

	storagePath := filepath.Join(s.BasePath, sha256Hash)

	storedFile, err := os.Create(storagePath)
	if err != nil {
		return "", err
	}
	defer storedFile.Close()

	if _, err := io.Copy(storedFile, file); err != nil {
		return "", err
	}

	return storagePath, nil
}