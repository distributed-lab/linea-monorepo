package zkevm

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/spf13/viper"
	"os"
	"testing"
)

func TestAIR(t *testing.T) {
	traceFile := "./arithmetization/4181195-4181272.conflated.v0.8.0-rc3.lt"
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

	zkevm.Arithmetization().Assign(&prover, traceFile)

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

	fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN")).Pretty())
	fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN_perm")).Pretty())

	fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN")).Len())
	fmt.Println(prover.Columns.MustGet(ifaces.ColID("mxp.CN_perm")).Len())

	println("Dumping...")

	columns := make(map[string][]field.Element)
	for k, v := range prover.Columns.InnerMap() {
		data := make([]field.Element, v.Len())
		v.WriteInSlice(data)
		columns[string(k)] = data
	}

	println("Marshalling...")
	dump, err := json.Marshal(prover.Columns.InnerMap())
	if err != nil {
		panic(err)
	}

	println("Saving...")
	err = os.WriteFile("./dump.json", dump, 0644)
	if err != nil {
		panic(err)
	}

	//spew.Dump(trace.Modules())
	//spew.Dump(trace.Column(0))

	//cs := sch.Constraints().Nth(1).(*constraint.VanishingConstraint[constraint.ZeroTest[air.Expr]])
	//spew.Dump(cs)

	//i, ok := sch.Constraints().Find(func(s schema.Constraint) bool {
	//	_, ok := s.(*constraint.VanishingConstraint[constraint.ZeroTest[air.Expr]])
	//	return ok
	//})
	//
	//println(i, ok)
}
