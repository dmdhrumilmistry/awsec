package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ReadFileLines(filePath string) ([]string, error) {
	if _, err := os.Stat(filePath); err != nil {
		// Check for valid path using os.Stat
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file path does not exist: %s", filePath)
		}
		return nil, fmt.Errorf("error checking file path: %w", err)
	}

	var lines []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close() // Ensure file is closed even in case of errors

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, strings.TrimSpace(line)) // Trim whitespaces and append
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
