//go:build !linux

package provider

import "fmt"

func writeProviderFile(string, string, []byte) error {
	return fmt.Errorf("secure provider filesystem operations require Linux")
}

func writeProviderFileLimited(string, string, []byte, int64) error {
	return fmt.Errorf("secure provider filesystem operations require Linux")
}

func readProviderFile(string, string) ([]byte, error) {
	return nil, fmt.Errorf("secure provider filesystem operations require Linux")
}

func readProviderFileLimited(string, string, int64) ([]byte, error) {
	return nil, fmt.Errorf("secure provider filesystem operations require Linux")
}

func listProviderFiles(string, string) ([]string, error) {
	return nil, fmt.Errorf("secure provider filesystem operations require Linux")
}
