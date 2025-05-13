package common

// LimbBytes is the size of one limb in bytes
const LimbBytes = 2

// DivideBytes splits the input slice into subarrays of the size defined by LimbBytes.
func DivideBytes(input []byte) [][]byte {
	if len(input) == 0 {
		return [][]byte{}
	}

	var result [][]byte
	for i := 0; i < len(input); i += LimbBytes {
		end := i + LimbBytes
		if end > len(input) {
			end = len(input)
		}
		result = append(result, input[i:end])
	}
	return result
}
