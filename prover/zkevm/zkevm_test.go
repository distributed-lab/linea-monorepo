package zkevm

import (
	"fmt"
	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/query"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/viper"
	"os"
	"testing"
)

func TestAIR(t *testing.T) {
	traceFile := "./arithmetization/4181039-4181116.conflated.v0.8.0-rc3.lt"
	cfgFile := "../config/config-integration-full.toml"

	//schema, err := ReadZkevmBin()
	//if err != nil {
	//	panic(err)
	//}

	viper.Set("assets_dir", "../prover-assets")

	cfg, err := config.NewConfigFromFile(cfgFile)
	if err != nil {
		panic(err)
	}

	zkevm := FullZkEVMCheckOnly(&cfg.TracesLimits)

	prover := zkevm.WizardIOP.CreateProver()

	zkevm.arithmetization.Assign(&prover, traceFile)

	//compiledIOP := &wizard.CompiledIOP{
	//	Columns:         column.NewStore(),
	//	QueriesParams:   wizard.NewRegister[ifaces.QueryID, ifaces.Query](),
	//	QueriesNoParams: wizard.NewRegister[ifaces.QueryID, ifaces.Query](),
	//	Coins:           wizard.NewRegister[coin.Name, coin.Info](),
	//	Precomputed:     collection.NewMapping[ifaces.ColID, ifaces.ColAssignment](),
	//}
	//
	//Define(compiledIOP, schema, &cfg.TracesLimits)
	//
	//trace, err := ReadLtTraces(files.MustRead(traceFile), schema)
	//if err != nil {
	//	panic(err)
	//}

	//runtime := compiledIOP.CreateProver()
	//AssignFromLtTraces(&runtime, schema, trace, &cfg.TracesLimits)

	//list := []string{"mxp.CN", "mxp.STAMP", "mxp.C_MEM", "mxp.C_MEM_NEW", "mxp.WORDS", "mxp.WORDS_NEW", "mxp.CN_perm", "mxp.STAMP_perm", "mxp.C_MEM_perm", "mxp.C_MEM_NEW_perm", "mxp.WORDS_perm", "mxp.WORDS_NEW_perm"}

	//fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN")).Pretty())
	//fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN_perm")).Pretty())
	//
	//fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN")).Len())
	//	fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN_perm")))

	//println("Dumping...")
	//
	//columns := make(map[string][]field.Element)
	//for k, v := range prover.Columns.InnerMap() {
	//	data := make([]field.Element, v.Len())
	//	v.WriteInSlice(data)
	//	columns[string(k)] = data
	//}

	//for _, k := range prover.Spec.QueriesNoParams.AllKeys() {
	//	if strings.Contains(string(k), "bin-into-binreftable-high") {
	//		//fmt.Println(k)
	//		//fmt.Println(prover.Spec.QueriesNoParams.Data(k))
	//		q := prover.Spec.QueriesNoParams.Data(k).(query.Inclusion)
	//
	//		fmt.Println("name", q.Name())
	//		fmt.Println("included", q.Included)
	//		fmt.Println("including", q.Including)
	//
	//		fmt.Println("included filter", q.IncludedFilter)
	//		fmt.Println("including filter", q.IncludingFilter)
	//
	//		fmt.Println(q.Included[0].GetColAssignment(&prover))
	//
	//	}
	//}

	//println("Marshalling...")
	//dump, err := json.Marshal(prover.Columns.ListAllKeys())
	//if err != nil {
	//	panic(err)
	//}
	//
	//println("Saving...")
	//err = os.WriteFile("./dump_keys.json", dump, 0644)
	//if err != nil {
	//	panic(err)
	//}

	for _, k := range prover.Spec.QueriesNoParams.AllKeys() {
		switch q := prover.Spec.QueriesNoParams.Data(k).(type) {
		case query.Permutation:
			parsePermutationQuery(&prover, q)
		case query.Inclusion:
			parseLookupQuery(&prover, q)
			return
		}
	}
}

var permCounter, lookupCounter = 0, 0

type Element = []byte

func parsePermutationQuery(runtime *wizard.ProverRuntime, q query.Permutation) {
	fmt.Printf("Found permutation: %s\n", q.ID)

	type JSONPermutation struct {
		Name string      `json:"name"`
		A    [][]Element `json:"a"`
		B    [][]Element `json:"b"`
	}

	model := JSONPermutation{
		Name: string(q.ID),
		A:    make([][]Element, 0, len(q.A[0])),
		B:    make([][]Element, 0, len(q.B[0])),
	}

	for _, column := range q.A[0] {
		v := column.GetColAssignment(runtime)
		data := make([]field.Element, v.Len())
		v.WriteInSlice(data)
		model.A = append(model.A, parseElementArray(data))
	}

	for _, column := range q.B[0] {
		v := column.GetColAssignment(runtime)
		data := make([]field.Element, v.Len())
		v.WriteInSlice(data)
		model.B = append(model.B, parseElementArray(data))
	}

	println("Marshalling...")
	dump, err := cbor.Marshal(model)
	if err != nil {
		panic(err)
	}

	println("Saving...")
	err = os.WriteFile(fmt.Sprintf("./trace/permutation_%d.bin", permCounter), dump, 0644)
	if err != nil {
		panic(err)
	}

	permCounter++

	fmt.Println("Processing finished")
}

func parseLookupQuery(runtime *wizard.ProverRuntime, q query.Inclusion) {
	fmt.Printf("Found lookup: %s\n", q.ID)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Failed to parse", r)
		}

		lookupCounter++
		fmt.Println("Processing finished")
	}()

	type JSONLookup struct {
		Name    string      `json:"name"`
		A       [][]Element `json:"a"`
		B       [][]Element `json:"b"`
		AFilter []Element   `json:"a_filter"`
		BFilter []Element   `json:"b_filter"`
	}

	var aFilter []field.Element
	var bFilter []field.Element

	if q.IncludedFilter != nil && q.IncludedFilter.Size() > 0 {
		aFilter = make([]field.Element, q.IncludedFilter.Size())
		q.IncludedFilter.GetColAssignment(runtime).WriteInSlice(aFilter)
	}

	a := make([][]Element, 0, len(q.Included))
	for _, column := range q.Included {
		data := make([]field.Element, column.GetColAssignment(runtime).Len())
		column.GetColAssignment(runtime).WriteInSlice(data)
		a = append(a, parseElementArray(data))
	}

	for i := range len(q.Including) {
		fmt.Printf("Processing %d-th\n", i)

		if q.IncludingFilter != nil && q.IncludingFilter[i].Size() > 0 {
			bFilter = make([]field.Element, q.IncludingFilter[i].Size())
			q.IncludingFilter[i].GetColAssignment(runtime).WriteInSlice(bFilter)
		}

		model := JSONLookup{
			Name:    string(q.ID),
			A:       a,
			B:       nil,
			AFilter: parseElementArray(aFilter),
			BFilter: parseElementArray(bFilter),
		}

		b := make([][]Element, 0, len(q.Including[i]))
		for _, column := range q.Including[i] {
			data := make([]field.Element, column.GetColAssignment(runtime).Len())
			column.GetColAssignment(runtime).WriteInSlice(data)
			b = append(b, parseElementArray(data))
		}

		model.B = b

		println("Marshalling...")
		dump, err := cbor.Marshal(model)
		if err != nil {
			panic(err)
		}

		println("Saving...")
		err = os.WriteFile(fmt.Sprintf("./trace/lookup_%d_%d.bin", lookupCounter, i), dump, 0644)
		if err != nil {
			panic(err)
		}
	}
}

func parseElementArray(v []field.Element) []Element {
	e := make([]Element, len(v))
	var buf [32]byte
	for i, x := range v {
		buf = x.Bytes()
		e[i] = buf[:]
	}
	return e
}
