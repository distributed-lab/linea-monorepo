package prover

import (
	crrand "crypto/rand"
	"encoding/csv"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	fr_secp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/linea-monorepo/prover/backend/files"
	"github.com/consensys/linea-monorepo/prover/crypto/keccak"
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/utils"
	"github.com/consensys/linea-monorepo/prover/utils/csvtraces"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
	zkecdsa "github.com/consensys/linea-monorepo/prover/zkevm/prover/ecdsa"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/generic"
	"golang.org/x/crypto/sha3"
	"math/big"
	"math/rand/v2"
	"os"
	"strings"
)

const LimbBytes = 2

func assignTxnDataFromPK(
	run *wizard.ProverRuntime,
	rlpTxnHashes [][32]byte,
	nbRowsPerTxInTxnData int,
	maxNbTx int,
	inputSize int,
) {
	var (
		hasher = sha3.NewLegacyKeccak256()
	)
	// compute the hash of public keys
	pkHash := make([][]byte, 0, len(rlpTxnHashes))
	for i := range rlpTxnHashes {
		pk, _, _, _, err := generateDeterministicSignature(rlpTxnHashes[i][:])
		if err != nil {
			utils.Panic("error generating signature")
		}
		buf := pk.A.RawBytes()

		hasher.Write(buf[:])
		res := hasher.Sum(nil)
		hasher.Reset()

		pkHash = append(pkHash, res)
	}

	// now assign  txn_data from the hash results.
	// populate the CT column
	var ctWit []field.Element
	for i := 0; i < maxNbTx; i++ {
		for j := 0; j < nbRowsPerTxInTxnData; j++ {
			ctWit = append(ctWit, field.NewElement(uint64(j+1)))
		}
	}

	// populate the columns FromHi and FromLo
	from := make([][]field.Element, 0, common.NbLimbU256)
	for i := 0; i < common.NbLimbU256; i++ {
		from = append(from, make([]field.Element, maxNbTx*nbRowsPerTxInTxnData))
	}

	for i := 0; i < len(pkHash); i++ {
		fromLimbs := splitBytes(pkHash[i])

		for j, limb := range fromLimbs {
			// Initialize limb values for each column of from
			from[j][i*nbRowsPerTxInTxnData].SetBytes(limb[:])
		}
	}

	// these are arithmetization columns, so LeftZeroPad
	for i := 0; i < common.NbLimbU256; i++ {
		run.AssignColumn(ifaces.ColIDf("txndata.FROM_%d", i), smartvectors.LeftZeroPadded(from[i], inputSize))
	}

	run.AssignColumn("txndata.CT", smartvectors.LeftZeroPadded(ctWit, inputSize))
}

func generateDeterministicSignature(txHash []byte) (pk *ecdsa.PublicKey, r, s, v *big.Int, err error) {
	reader := sha3.NewShake128()
	reader.Write(txHash)
	for i := 0; i < 10; i++ {
		r, err := crrand.Int(reader, fr_secp256k1.Modulus())
		if err != nil {
			return nil, nil, nil, nil, err
		}
		s, err := crrand.Int(reader, fr_secp256k1.Modulus())
		if err != nil {
			return nil, nil, nil, nil, err
		}
		var v uint = 0
		pk = new(ecdsa.PublicKey)
		if err = pk.RecoverFrom(txHash, v, r, s); err == nil {
			return pk, r, s, new(big.Int).SetUint64(uint64(v + 27)), nil
		}
	}
	return nil, nil, nil, nil, fmt.Errorf("failed to generate a valid signature")
}

// splitBytes splits the input slice into subarrays of the provided size.
func splitBytes(input []byte) [][]byte {
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

func generateAndAssignGenDataModule(run *wizard.ProverRuntime, gdm *generic.GenDataModule,
	hashNumInt, toHashInt []int, flag bool, path ...string) {

	var (
		size    = gdm.Limbs[0].Size()
		nBytes  = make([]field.Element, size)
		toHash  = make([]field.Element, size)
		index   = make([]field.Element, size)
		hashNum = make([]field.Element, size)

		limbs    [common.NbLimbU128][]field.Element
		limbCols [common.NbLimbU128]*common.VectorBuilder

		rng = rand.New(rand.NewChaCha8([32]byte{}))

		nByteCol   = common.NewVectorBuilder(gdm.NBytes)
		hashNumCol = common.NewVectorBuilder(gdm.HashNum)
		toHashCol  = common.NewVectorBuilder(gdm.ToHash)
		indexCol   = common.NewVectorBuilder(gdm.Index)
	)

	for i := 0; i < common.NbLimbU128; i++ {
		limbCols[i] = common.NewVectorBuilder(gdm.Limbs[i])
	}

	for i := range hashNumInt {

		if i == 0 {
			index[i] = field.Zero()
		} else if hashNumInt[i] != hashNumInt[i-1] {
			index[i] = field.Zero()
		} else if toHashInt[i] == 0 {
			index[i] = index[i-1]
		} else {
			index[i].Add(&index[i-1], new(field.Element).SetOne())
		}

		toHash[i] = field.NewElement(uint64(toHashInt[i]))
		hashNum[i] = field.NewElement(uint64(hashNumInt[i]))
		var numBytesInt int
		var numBytesF field.Element
		if flag {
			numBytesInt, numBytesF = randNBytes(rng)
			nBytes[i] = numBytesF
		} else {
			nBytes[i] = field.NewElement(16)
			numBytesInt = 16
		}

		randElement := randLimbs(rng, numBytesInt)
		limbBytes := randElement.Bytes()
		dividedLimbs := splitBytes(limbBytes[16:])

		for j, limb := range dividedLimbs {
			var bytes [16]byte
			copy(bytes[:], limb)

			var l field.Element
			l.SetBytes(bytes[:])

			limbs[j] = append(limbs[j], l)
		}

	}

	nByteCol.PushSliceF(nBytes)
	hashNumCol.PushSliceF(hashNum)
	indexCol.PushSliceF(index)
	toHashCol.PushSliceF(toHash)

	for i, col := range limbCols {
		col.PushSliceF(limbs[i])
		col.PadAndAssign(run)
	}

	nByteCol.PadAndAssign(run)
	hashNumCol.PadAndAssign(run)
	indexCol.PadAndAssign(run)
	toHashCol.PadAndAssign(run)

	if len(path) > 0 {

		oF := files.MustOverwrite(path[0])
		fmt.Fprint(oF, "TO_HASH,HASH_NUM,INDEX,NBYTES,LIMBS\n")

		for i := range hashNumInt {
			var limbsStr []string
			for _, l := range limbs[i] {
				limbsStr = append(limbsStr, fmt.Sprintf("0x%s", l.Text(16)))
			}

			fmt.Fprintf(oF, "%v,%v,%v,%v,0x%v\n",
				toHash[i].String(),
				hashNum[i].String(),
				index[i].String(),
				nBytes[i].String(),
				strings.Join(limbsStr, ","),
			)
		}

		oF.Close()
	}

}

func randNBytes(rng *rand.Rand) (int, field.Element) {

	// nBytesInt must be in 1..=16
	var (
		nBytesInt = rng.Int32N(16) + 1
		nBytesF   = field.NewElement(uint64(nBytesInt))
	)

	return int(nBytesInt), nBytesF
}

func randLimbs(rng *rand.Rand, nBytes int) field.Element {

	var (
		resBytes = make([]byte, 16)
		_, _     = utils.ReadPseudoRand(rng, resBytes[:nBytes])
		res      = new(field.Element).SetBytes(resBytes)
	)

	return *res
}

func createColFn(comp *wizard.CompiledIOP, rootName string, size int) func(name string, args ...interface{}) ifaces.Column {

	return func(name string, args ...interface{}) ifaces.Column {
		s := []string{rootName, name}

		v := strings.Join(s, ".")

		return comp.InsertCommit(0, ifaces.ColIDf(v, args...), size)
	}

}

func createGenDataModule(
	comp *wizard.CompiledIOP,
	name string,
	size int,
) (gbm generic.GenDataModule) {
	createCol := createColFn(comp, name, size)
	gbm.HashNum = createCol("ABS_TX_NUM")
	gbm.Index = createCol("INDEX_LX")

	for i := 0; i < common.NbLimbU128; i++ {
		gbm.Limbs = append(gbm.Limbs, createCol("LIMB_%d", i))
	}

	gbm.NBytes = createCol("nBYTES")
	gbm.ToHash = createCol("TO_HASH_BY_PROVER")
	return gbm
}

func commit(comp *wizard.CompiledIOP, names []string, size int) {
	for _, name := range names {
		comp.InsertCommit(0, ifaces.ColIDf(name), size)
	}

	comp.InsertCommit(0, "txndata.CT", size)

	for i := 0; i < 16; i++ {
		comp.InsertCommit(0, ifaces.ColIDf("txndata.FROM_%d", i), size)
	}
}

func readCSVColumns(filename string) ([]string, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Create a CSV reader
	reader := csv.NewReader(file)

	// Read the first row, which should contain the column names
	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read column names: %w", err)
	}

	return headers, nil
}

func readFile(name string) (*csvtraces.CsvTrace, []string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	ct, err := csvtraces.NewCsvTrace(f)
	if err != nil {
		return nil, nil, err
	}

	names, err := readCSVColumns(name)
	if err != nil {
		return nil, nil, err
	}

	return ct, names, nil
}

func assignEcdsa(run *wizard.ProverRuntime, rlpTxn *generic.GenDataModule, c makeTestCase, limits *zkecdsa.Settings, size int, nbRowsPerTxInTxnData int) {
	// assign data to rlp_txn module
	generateAndAssignGenDataModule(run, rlpTxn, c.HashNum, c.ToHash, true)

	trace := keccak.GenerateTrace(rlpTxn.ScanStreams(run))
	assignTxnDataFromPK(run, trace.HashOutPut, nbRowsPerTxInTxnData, limits.MaxNbTx, size)
}

func dummyTxSignatureGetter(i int, txHash []byte) (r, s, v *big.Int, err error) {
	// some dummy values from the traces
	m := map[[32]byte]struct{ r, s, v string }{
		{0x27, 0x9d, 0x94, 0x62, 0x15, 0x58, 0xf7, 0x55, 0x79, 0x68, 0x98, 0xfc, 0x4b, 0xd3, 0x6b, 0x6d, 0x40, 0x7c, 0xae, 0x77, 0x53, 0x78, 0x65, 0xaf, 0xe5, 0x23, 0xb7, 0x9c, 0x74, 0xcc, 0x68, 0xb}: {
			r: "c2ff96feed8749a5ad1c0714f950b5ac939d8acedbedcbc2949614ab8af06312",
			s: "1feecd50adc6273fdd5d11c6da18c8cfe14e2787f5a90af7c7c1328e7d0a2c42",
			v: "1b",
		},
		{0x4b, 0xe1, 0x46, 0xe0, 0x6c, 0xc1, 0xb3, 0x73, 0x42, 0xb6, 0xb7, 0xb1, 0xfa, 0x85, 0x42, 0xae, 0x58, 0xa6, 0x21, 0x3, 0xb8, 0xaf, 0xf, 0x7d, 0x58, 0xf8, 0xa1, 0xff, 0xff, 0xcf, 0x79, 0x14}: {
			r: "a7b0f504b652b3a621921c78c587fdf80a3ab590e22c304b0b0930e90c4e081d",
			s: "5428459ef7e6bd079fbbb7c6fd95cc6c7fe68c93ed4ae75cee36810e79e8a0e5",
			v: "1b",
		},
		{0xca, 0x3e, 0x75, 0x57, 0xa, 0xea, 0xe, 0x3d, 0xd8, 0xe7, 0xa9, 0xd3, 0x8c, 0x2e, 0xfa, 0x86, 0x6f, 0x5e, 0xe2, 0xb1, 0x8b, 0xf5, 0x27, 0xa0, 0xf4, 0xe3, 0x24, 0x8b, 0x7c, 0x7c, 0xf3, 0x76}: {
			r: "f1136900c2cd16eacc676f2c7b70f3dfec13fd16a426aab4eda5d8047c30a9e9",
			s: "4dad8f009ebe31bdc38133bc5fa60e9dca59d0366bd90e2ef12b465982c696aa",
			v: "1c",
		},
	}
	var txHashA [32]byte
	copy(txHashA[:], txHash)
	if v, ok := m[txHashA]; ok {
		r, ok = new(big.Int).SetString(v.r, 16)
		if !ok {
			utils.Panic("failed to parse r")
		}
		s, ok = new(big.Int).SetString(v.s, 16)
		if !ok {
			utils.Panic("failed to parse s")
		}
		vv, ok := new(big.Int).SetString(v.v, 16)
		if !ok {
			utils.Panic("failed to parse v")
		}
		return r, s, vv, nil
	}
	// if not found, create a random signature (which results in random public key)
	_, r, s, v, err = generateDeterministicSignature(txHash)
	if err != nil {
		return nil, nil, nil, err
	}

	return r, s, v, nil
}
