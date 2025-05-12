package common

// LimbSize is the size of one limb in bytes
const LimbSize = 2

// DivideBytes splits the input slice into subarrays of the size defined by LimbSize.
func DivideBytes(input []byte) [][]byte {
	if len(input) == 0 {
		return [][]byte{}
	}

	var result [][]byte
	for i := 0; i < len(input); i += LimbSize {
		end := i + LimbSize
		if end > len(input) {
			end = len(input)
		}
		result = append(result, input[i:end])
	}
	return result
}
