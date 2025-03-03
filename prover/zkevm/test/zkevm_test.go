package test

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/linea-monorepo/prover/backend/execution"
	"github.com/consensys/linea-monorepo/prover/config"
	sv "github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/coin"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/query"
	"github.com/consensys/linea-monorepo/prover/protocol/variables"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/utils"
	zkevm2 "github.com/consensys/linea-monorepo/prover/zkevm"
	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/viper"
	"os"
	"reflect"
	"testing"
)

const Save = true
const TargetHeight = 1 << 16

func ReadRequest(path string, into any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(into); err != nil {
		return fmt.Errorf("could not decode input file: %w", err)
	}

	return nil
}

func TestAIR(t *testing.T) {
	traceFile := "/root/data/conflated/1-57.conflated.v0.8.0-rc8.lt"
	//traceFile := "/Users/olegfomenko/Documents/Linea/test/conflated/1-57.conflated.v0.8.0-rc8.lt"

	requestFile := "/root/data/requests/1-57-etv0.2.0-stv2.2.0-getZkProof.json"
	//requestFile := "/Users/olegfomenko/Documents/Linea/test/requests/1-57-etv0.2.0-stv2.2.0-getZkProof.json"

	cfgFile := "../../config/config-sepolia-full.toml"

	req := &execution.Request{}
	if err := ReadRequest(requestFile, req); err != nil {
		panic(err)
	}

	viper.Set("assets_dir", "../../prover-assets")

	cfg, err := config.NewConfigFromFile(cfgFile)
	if err != nil {
		panic(err)
	}

	zkevm := zkevm2.FullZkEVMEmpty(&cfg.TracesLimits)

	prover := zkevm.WizardIOP.CreateProver()
	out := execution.CraftProverOutput(cfg, req)
	witness := execution.NewWitness(cfg, req, &out)
	input := witness.ZkEVM
	input.ExecTracesFPath = traceFile
	zkevm.Prove(input)(&prover)

	for _, subprover := range zkevm.WizardIOP.SubProvers.MustGet(0) {
		subprover(&prover)
	}

	for _, k := range prover.Spec.QueriesNoParams.AllKeysAt(0) {
		switch q := prover.Spec.QueriesNoParams.Data(k).(type) {
		//case query.Permutation:
		//	parsePermutationQuery(&prover, q)
		//case query.Inclusion:
		//	parseLookupQuery(&prover, q)
		//case query.Range:
		//	parseRangeQuery(&prover, q)
		case query.GlobalConstraint:
			parseGlobalQuery(&prover, q)
		}
	}

	fmt.Printf("Total count:\n\tGlobal: %d\n\t", globalCounter)
}

var permCounter, lookupCounter, rangeCounter, globalCounter = 0, 0, 0, 0

func parseGlobalQuery(runtime *wizard.ProverRuntime, q query.GlobalConstraint) {
	fmt.Printf("Found globla: %s\n", q.ID)

	board := q.Board()
	metadatas := board.ListVariableMetadata()

	//fmt.Println("Range:", q.MinMaxOffset())

	model := JSONGlobal{
		Inputs:    make([][]Element, len(metadatas)),
		InputsIds: make([]string, len(metadatas)),
		Nodes:     make([][]Node, len(board.Nodes)),
	}

	start := 0
	stop := q.DomainSize

	if !q.NoBoundCancel {
		start -= q.MinMaxOffset().Min
		stop -= q.MinMaxOffset().Max
	}

	model.Start = start
	model.Stop = stop

	for k, metadataInterface := range metadatas {
		switch meta := metadataInterface.(type) {
		case ifaces.Column:
			w := meta.GetColAssignment(runtime)
			data := make([]field.Element, w.Len())
			w.WriteInSlice(data)
			model.Inputs[k] = parseElementArray(data)
			model.InputsIds[k] = string(meta.GetColID())
		case coin.Info:
			// TODO
			w := sv.NewConstant(runtime.GetRandomCoinField(meta.Name), q.DomainSize)
			data := make([]field.Element, w.Len())
			w.WriteInSlice(data)
			model.Inputs[k] = parseElementArray(data)
		case variables.X:
			w := meta.EvalCoset(q.DomainSize, 0, 1, false)
			data := make([]field.Element, w.Len())
			w.WriteInSlice(data)
			model.Inputs[k] = parseElementArray(data)
		case variables.PeriodicSample:
			w := meta.EvalCoset(q.DomainSize, 0, 1, false)
			data := make([]field.Element, w.Len())
			w.WriteInSlice(data)
			model.Inputs[k] = parseElementArray(data)
		case ifaces.Accessor:
			w := sv.NewConstant(meta.GetVal(runtime), q.DomainSize)
			data := make([]field.Element, w.Len())
			w.WriteInSlice(data)
			model.Inputs[k] = parseElementArray(data)
		default:
			utils.Panic("Not a variable type %v in query %v", reflect.TypeOf(metadataInterface), q.ID)
		}
	}

	for i := range len(board.Nodes) {
		for j, node := range board.Nodes[i] {
			data := Node{
				Children: make([]uint64, len(node.Children)),
				Operator: Operator{},
			}

			for idx, x := range node.Children {
				data.Children[idx] = uint64(x)
			}

			switch op := node.Operator.(type) {
			case symbolic.Constant:
				data.Operator.Typ = 0
				data.Operator.Value = op.Val.Bytes()
			case symbolic.LinComb:
				data.Operator.Typ = 1
				data.Operator.Coeffs = op.Coeffs
			case symbolic.PolyEval:
				data.Operator.Typ = 2
			case symbolic.Product:
				data.Operator.Typ = 3
				data.Operator.Coeffs = op.Exponents
			case symbolic.Variable:
				data.Operator.Typ = 4
				data.Operator.Id = j
			}

			model.Nodes[i] = append(model.Nodes[i], data)
		}
	}

	if !Save {
		return
	}

	models := model.splitColumns(TargetHeight)

	for _, model := range models {
		if !model.isActive() {
			continue
		}

		println("Marshalling...")
		dump, err := cbor.Marshal(model)
		if err != nil {
			panic(err)
		}

		println("Saving...")
		err = os.WriteFile(fmt.Sprintf("../trace/global%d.bin", globalCounter), dump, 0644)
		if err != nil {
			panic(err)
		}

		globalCounter++
	}

	fmt.Println("Processing finished")
}

func parsePermutationQuery(runtime *wizard.ProverRuntime, q query.Permutation) {
	fmt.Printf("Found permutation: %s\n", q.ID)

	model := JSONPermutation{
		Name: string(q.ID),
		A:    make([][]Element, 0, len(q.A[0])),
		B:    make([][]Element, 0, len(q.B[0])),
		AIds: make([]string, 0, len(q.A[0])),
		BIds: make([]string, 0, len(q.B[0])),
	}

	for _, column := range q.A[0] {
		v := column.GetColAssignment(runtime)
		data := make([]field.Element, v.Len())
		v.WriteInSlice(data)
		model.A = append(model.A, parseElementArray(data))
		model.AIds = append(model.AIds, string(column.GetColID()))
	}

	for _, column := range q.B[0] {
		v := column.GetColAssignment(runtime)
		data := make([]field.Element, v.Len())
		v.WriteInSlice(data)
		model.B = append(model.B, parseElementArray(data))
		model.BIds = append(model.BIds, string(column.GetColID()))
	}

	if !Save {
		return
	}

	println("Marshalling...")
	dump, err := cbor.Marshal(model)
	if err != nil {
		panic(err)
	}

	println("Saving...")
	err = os.WriteFile(fmt.Sprintf("../trace/permutation_%d.bin", permCounter), dump, 0644)
	if err != nil {
		panic(err)
	}

	permCounter++

	fmt.Println("Processing finished")
}

func parseLookupQuery(runtime *wizard.ProverRuntime, q query.Inclusion) {
	fmt.Printf("Found lookup: %s\n", q.ID)

	var aFilter []field.Element

	if q.IsFilteredOnIncluded() {
		aFilter = make([]field.Element, q.IncludedFilter.Size())
		q.IncludedFilter.GetColAssignment(runtime).WriteInSlice(aFilter)
	}

	a := make([][]Element, 0, len(q.Included))
	aids := make([]string, 0, len(q.Included))

	//sz := 0
	for _, column := range q.Included {
		data := make([]field.Element, column.GetColAssignment(runtime).Len())
		column.GetColAssignment(runtime).WriteInSlice(data)
		a = append(a, parseElementArray(data))
		aids = append(aids, string(column.GetColID()))

		//curSz := column.GetColAssignment(runtime).Len()
		//if sz == 0 {
		//	sz = curSz
		//} else if sz != curSz {
		//	panic(fmt.Sprintf("A: sz = %d, cur sz = %d", sz, curSz))
		//}
	}

	model := JSONLookup{
		Name:    string(q.ID),
		A:       [][][]Element{a},
		AIds:    [][]string{aids},
		B:       make([][][]Element, 0, len(q.IncludingFilter)),
		BIds:    make([][]string, 0, len(q.IncludingFilter)),
		AFilter: [][]Element{parseElementArray(aFilter)},
		BFilter: make([][]Element, 0, len(q.IncludingFilter)),
	}

	for i := range len(q.Including) {
		var bFilter []field.Element

		if q.IsFilteredOnIncluding() {
			bFilter = make([]field.Element, q.IncludingFilter[i].Size())
			q.IncludingFilter[i].GetColAssignment(runtime).WriteInSlice(bFilter)
		}

		model.BFilter = append(model.BFilter, parseElementArray(bFilter))

		//sz := 0

		b := make([][]Element, 0, len(q.Including[i]))
		bids := make([]string, 0, len(q.Including[i]))
		for _, column := range q.Including[i] {
			data := make([]field.Element, column.GetColAssignment(runtime).Len())
			column.GetColAssignment(runtime).WriteInSlice(data)
			b = append(b, parseElementArray(data))
			bids = append(bids, string(column.GetColID()))

			//curSz := column.GetColAssignment(runtime).Len()
			//if sz == 0 {
			//	sz = curSz
			//} else if sz != curSz {
			//	panic(fmt.Sprintf("B: sz = %d, cur sz = %d", sz, curSz))
			//}
		}

		model.B = append(model.B, b)
		model.BIds = append(model.BIds, bids)
	}

	model.splitAll(TargetHeight)

	if !Save {
		return
	}

	println("Marshalling...")
	dump, err := cbor.Marshal(model)
	if err != nil {
		panic(err)
	}

	println("Saving...")
	err = os.WriteFile(fmt.Sprintf("../trace/lookup_%d.bin", lookupCounter), dump, 0644)
	if err != nil {
		panic(err)
	}

	lookupCounter++
	fmt.Println("Processing finished")

}

func parseRangeQuery(runtime *wizard.ProverRuntime, q query.Range) {
	fmt.Printf("Found range: %s\n", q.ID)

	model := JSONRange{
		Name: string(q.ID),
		A:    nil,
		AIds: []string{string(q.Handle.GetColID())},
		B:    q.B,
	}

	v := q.Handle.GetColAssignment(runtime)
	data := make([]field.Element, v.Len())
	v.WriteInSlice(data)
	model.A = [][]Element{parseElementArray(data)}

	model.splitAll(TargetHeight)

	if !Save {
		return
	}

	println("Marshalling...")
	dump, err := cbor.Marshal(model)
	if err != nil {
		panic(err)
	}

	println("Saving...")
	err = os.WriteFile(fmt.Sprintf("../trace/range_%d.bin", rangeCounter), dump, 0644)
	if err != nil {
		panic(err)
	}

	rangeCounter++

	fmt.Println("Processing finished")
}
