package testdata

import (
	"encoding/csv"
	"os"
	"testing"
)

// TestMergeModules merges provided csv input files into one
func TestMergeModules(t *testing.T) {
	inputFiles := []string{
		"antichamber.csv",
		"ecadd_test.csv",
		"ecmul_test.csv",
		"ecpair_double_pair_input.csv",
		"single_256_bits_input.csv",
	}

	outputFile := "merged.csv"

	sourceFile := inputFiles[0]
	for i := 1; i < len(inputFiles); i++ {
		err := mergeCSVFilesByHeaders(sourceFile, inputFiles[i], outputFile)
		if err != nil {
			t.Fatalf("Failed to merge files: %v", err)
		}
		sourceFile = outputFile
	}

	// Validate the output file
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("Output file %s was not created", outputFile)
	}
}

// mergeCSVFilesByHeaders reads two CSV files, aligns their data by headers, and writes the result to a new file.
func mergeCSVFilesByHeaders(file1, file2, outputFile string) error {
	// Read the first file
	data1, err := readCSV(file1)
	if err != nil {
		return err
	}

	// Read the second file
	data2, err := readCSV(file2)
	if err != nil {
		return err
	}

	// Extract headers
	headers1 := data1[0]
	headers2 := data2[0]

	// Create a unified header list
	headerMap := make(map[string]int)
	var unifiedHeaders []string
	for _, header := range headers1 {
		headerMap[header] = len(unifiedHeaders)
		unifiedHeaders = append(unifiedHeaders, header)
	}
	for _, header := range headers2 {
		if _, exists := headerMap[header]; !exists {
			headerMap[header] = len(unifiedHeaders)
			unifiedHeaders = append(unifiedHeaders, header)
		}
	}

	// Prepare data aligned to the unified headers
	alignedData := [][]string{unifiedHeaders}
	alignedData = append(alignedData, alignDataByHeaders(data1[1:], headers1, headerMap)...)
	alignedData = append(alignedData, alignDataByHeaders(data2[1:], headers2, headerMap)...)

	// Write the aligned data to the output file
	return createCSV(outputFile, alignedData)
}

// alignDataByHeaders aligns rows to the unified header map, filling missing columns with "0".
func alignDataByHeaders(data [][]string, headers []string, headerMap map[string]int) [][]string {
	aligned := make([][]string, len(data))
	for i, row := range data {
		alignedRow := make([]string, len(headerMap))
		// Initialize all fields with "0"
		for j := range alignedRow {
			alignedRow[j] = "0"
		}
		for j, value := range row {
			header := headers[j]
			if idx, exists := headerMap[header]; exists {
				alignedRow[idx] = value
			}
		}
		aligned[i] = alignedRow
	}
	return aligned
}

// readCSV reads the content of a CSV file and returns it as a slice of string slices.
func readCSV(filename string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	return reader.ReadAll()
}

// createCSV writes a slice of string slices to a CSV file.
func createCSV(filename string, data [][]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	return writer.WriteAll(data)
}
