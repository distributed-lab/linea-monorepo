package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

// Data represents a row in the CSV file
type Data struct {
	IsActive                                      string
	IsPushing                                     string
	IsFetching                                    string
	Source                                        string
	Limb                                          string
	SuccessBit                                    string
	IsData                                        string
	IsRes                                         string
	TxHashHi                                      string
	TxHashLo                                      string
	EcdsaAntichamberUnalignedGnarkDataIsPublicKey string
	EcdsaAntichamberUnalignedGnarkDataGnarkIndex  string
	EcdsaAntichamberUnalignedGnarkDataGnarkData   string
}

type DataWrite struct {
	IsActive                                      string
	IsPushing                                     string
	IsFetching                                    string
	Source                                        string
	Limb                                          []string
	SuccessBit                                    string
	IsData                                        string
	IsRes                                         string
	TxHash                                        []string
	EcdsaAntichamberUnalignedGnarkDataIsPublicKey string
	EcdsaAntichamberUnalignedGnarkDataGnarkIndex  string
	EcdsaAntichamberUnalignedGnarkDataGnarkData   []string
}

func prependZeros(s string, desiredLength int) string {
	numZeros := desiredLength - len(s)
	if numZeros > 0 {
		s = strings.Repeat("0", numZeros) + s
	}
	return s
}

func splitIntoPairs(input string, desiredLength int) []string {
	if len(input) == 0 {
		return []string{}
	}

	input = prependZeros(input, desiredLength)

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

	var header = []string{"IS_ACTIVE", "IS_PUSHING", "IS_FETCHING", "SOURCE"}
	for i := 0; i < 8; i++ {
		header = append(header, fmt.Sprintf("LIMB_%d", i))
	}

	header = append(header, "SUCCESS_BIT", "IS_DATA", "IS_RES")

	for i := 0; i < 16; i++ {
		header = append(header, fmt.Sprintf("TX_HASH_%d", i))
	}

	header = append(header, "ECDSA_ANTICHAMBER_UNALIGNED_GNARK_DATA_IS_PUBLIC_KEY", "ECDSA_ANTICHAMBER_UNALIGNED_GNARK_DATA_GNARK_INDEX")

	for i := 0; i < 8; i++ {
		header = append(header, fmt.Sprintf("ECDSA_ANTICHAMBER_UNALIGNED_GNARK_DATA_GNARK_DATA_%d", i))
	}
	// Write the header row

	if err := writer.Write(header); err != nil {
		fmt.Println("Error writing header:", err)
		return
	}

	println(len(header))

	// Write each data entry to the CSV file

	for _, entry := range dataEntries {
		var row []string
		row = append(row, entry.IsActive, entry.IsPushing, entry.IsFetching, entry.Source)
		row = append(row, entry.Limb[:]...)
		row = append(row, entry.SuccessBit, entry.IsData, entry.IsRes)
		row = append(row, entry.TxHash[:]...)
		row = append(row, entry.EcdsaAntichamberUnalignedGnarkDataIsPublicKey, entry.EcdsaAntichamberUnalignedGnarkDataGnarkIndex)
		row = append(row, entry.EcdsaAntichamberUnalignedGnarkDataGnarkData[:]...)

		if err := writer.Write(row); err != nil {
			fmt.Println("Error writing row:", err)
			return
		}
	}
}

func main() {
	// Open the CSV file
	file, err := os.Open("unaligned_gnark_test.csv")
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
	for i, row := range rows[1:] {
		if len(row) != 13 {
			fmt.Printf("Skipping row %d due to incorrect number of columns\n", i+1)
			continue
		}

		limbRow := row[4]
		if len(limbRow) > 2 {
			limbRow = row[4][2:]
		}

		txHashHiRow := row[8]
		txHashLoRow := row[9]

		if len(txHashHiRow) > 2 {
			txHashHiRow = row[8][2:]
			txHashLoRow = row[9][2:]
		}

		gnarkDataRow := row[12]

		if len(gnarkDataRow) > 2 {
			gnarkDataRow = row[12][2:]
		}

		dataEntry := DataWrite{
			IsActive:   row[0],
			IsPushing:  row[1],
			IsFetching: row[2],
			Source:     row[3],
			Limb:       splitIntoPairs(limbRow, 32),
			SuccessBit: row[5],
			IsData:     row[6],
			IsRes:      row[7],
			TxHash:     splitIntoPairs(txHashHiRow+txHashLoRow, 64),
			EcdsaAntichamberUnalignedGnarkDataIsPublicKey: row[10],
			EcdsaAntichamberUnalignedGnarkDataGnarkIndex:  row[11],
			EcdsaAntichamberUnalignedGnarkDataGnarkData:   splitIntoPairs(gnarkDataRow, 32),
		}

		dataEntries = append(dataEntries, dataEntry)
	}

	writeCsv("module.csv", dataEntries)
}
