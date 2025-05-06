package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

type DataWrite struct {
	IsActive          string
	EcDataCsEcrecover string
	EcDataId          string
	EcDataIndex       string
	EcDataLimb        []string
	EcDataSuccessBit  string
	EcDataIsData      string
	EcDataIsRes       string
}

func prependZeros(s string, desiredLength int) string {
	numZeros := desiredLength - len(s)
	if numZeros > 0 {
		s = strings.Repeat("0", numZeros) + s
	}
	return s
}

func splitIntoPairs(input string) []string {
	if len(input) == 0 {
		return []string{}
	}

	input = prependZeros(input, 32)

	var result []string
	for i := 0; i < len(input); i += 4 {
		var inp string

		if i+4 > len(input) {
			inp = input[i:]
		} else {
			inp = input[i : i+4]
		}

		if inp == "0000" {
			result = append(result, "0x0")
		} else {
			result = append(result, "0x"+inp)
		}
	}

	return result
}

func writeCsv(name string, dataEntries []DataWrite) {
	// Open a new CSV file for writing
	file, err := os.Create(name)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Create a CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	var header = []string{"IS_ACTIVE", "EC_DATA_CS_ECRECOVER", "EC_DATA_ID", "EC_DATA_INDEX"}
	for i := 0; i < 8; i++ {
		header = append(header, fmt.Sprintf("EC_DATA_LIMB_%d", i))
	}

	header = append(header, []string{"EC_DATA_SUCCESS_BIT", "EC_DATA_IS_DATA", "EC_DATA_IS_RES"}...)
	// Write the header row

	if err := writer.Write(header); err != nil {
		fmt.Println("Error writing header:", err)
		return
	}

	// Write each data entry to the CSV file
	for _, entry := range dataEntries {
		var row []string
		row = append(row, entry.IsActive, entry.EcDataCsEcrecover, entry.EcDataId, entry.EcDataIndex)
		row = append(row, entry.EcDataLimb[:]...)
		row = append(row, entry.EcDataSuccessBit, entry.EcDataIsData, entry.EcDataIsRes)

		if err := writer.Write(row); err != nil {
			fmt.Println("Error writing row:", err)
			return
		}
	}
}

func main() {
	// Open the CSV file
	file, err := os.Open("antichamber.csv")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Create a new CSV reader
	reader := csv.NewReader(file)

	// Read all rows from the CSV file
	rows, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	// Ensure the file has a header row
	if len(rows) < 2 {
		fmt.Println("CSV file is empty or missing header row.")
		return
	}

	var dataEntries []DataWrite
	for _, row := range rows[1:] {

		dataEntry := DataWrite{
			IsActive:          row[0],
			EcDataCsEcrecover: row[1],
			EcDataId:          row[2],
			EcDataIndex:       row[3],
			EcDataLimb:        splitIntoPairs(row[4][2:]),
			EcDataSuccessBit:  row[5],
			EcDataIsData:      row[6],
			EcDataIsRes:       row[7],
		}

		dataEntries = append(dataEntries, dataEntry)
	}

	writeCsv("module.csv", dataEntries)

}
