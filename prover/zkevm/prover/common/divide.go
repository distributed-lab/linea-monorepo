package common

// DivideBytes splits the input slice into subarrays of 2 bytes each.
// If the input slice length is odd, the last subarray will contain a single byte.
func DivideBytes(input []byte) [][]byte {
	if len(input) == 0 {
		return [][]byte{}
	}

	var result [][]byte
	for i := 0; i < len(input); i += 2 {
		end := i + 2
		if end > len(input) {
			end = len(input)
		}
		result = append(result, input[i:end])
	}
	return result
}
