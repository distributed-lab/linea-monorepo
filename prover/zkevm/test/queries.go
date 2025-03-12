package test

import (
	"fmt"
	"github.com/consensys/linea-monorepo/prover/maths/field"
)

type Element = [32]byte

func parseElementArray(v []field.Element) []Element {
	e := make([]Element, len(v))
	for i, x := range v {
		//fr.LittleEndian.PutElement(&e[i], x)
		e[i] = x.Bytes()
	}
	return e
}

type Operator struct {
	Typ    byte    `json:"typ"`    // 0 - constant, 1 - lin, 2 - poly, 3 - prod, 4 - var
	Value  Element `json:"value"`  // for constant
	Coeffs []int   `json:"coeffs"` // for lincomb and prod
	Id     int     `json:"id"`     // for var
}

type Node struct {
	Children []uint64 `json:"children"`
	Operator Operator `json:"operator"`
}

type JSONGlobal struct {
	Inputs    [][]Element `json:"inputs"`
	InputsIds []string    `json:"inputs_ids"`
	Nodes     [][]Node    `json:"nodes"`
	Start     int         `json:"start"`
	Stop      int         `json:"stop"`
}

type JSONPermutation struct {
	Name string      `json:"name"`
	A    [][]Element `json:"a"`
	AIds []string    `json:"a_ids"`
	B    [][]Element `json:"b"`
	BIds []string    `json:"b_ids"`
}

type JSONLookup struct {
	Name    string        `json:"name"`
	AIds    [][]string    `json:"a_ids"`
	A       [][][]Element `json:"a"`
	B       [][][]Element `json:"b"`
	BIds    [][]string    `json:"b_ids"`
	AFilter [][]Element   `json:"a_filter"`
	BFilter [][]Element   `json:"b_filter"`
}

type JSONRange struct {
	Name string      `json:"name"`
	A    [][]Element `json:"a"`
	AIds []string    `json:"a_id"`
	B    int         `json:"b"`
}

func (j *JSONRange) heightA() int {
	return len(j.A[0])
}
func (j *JSONRange) heightB() int {
	return j.B
}

func (j *JSONRange) splitA() {
	sz := len(j.A)
	height := j.heightA()
	splitHeight := height >> 1

	for i := range sz {
		j.A = append(j.A, j.A[i][splitHeight:])
		j.A[i] = j.A[i][:splitHeight]
		j.AIds = append(j.AIds, fmt.Sprintf("%s_SPLIT_%d", j.AIds[i], splitHeight))
	}
}

func (j *JSONRange) splitAll(targetHeight int) {
	for j.heightA() > targetHeight {
		j.splitA()
	}
}

func (j *JSONLookup) heightA() int {
	height := 0
	for i := range j.A {
		for k := range j.A[i] {
			height = max(height, len(j.A[i][k]))
		}
	}

	return height
}

func (j *JSONLookup) heightB() int {
	height := 0
	for i := range j.B {
		for k := range j.B[i] {
			height = max(height, len(j.B[i][k]))
		}
	}

	return height
}

func (j *JSONLookup) isFilteredA() bool {
	return len(j.AFilter) > 0 && len(j.AFilter[0]) > 0
}

func (j *JSONLookup) isFilteredB() bool {
	return len(j.BFilter) > 0 && len(j.BFilter[0]) > 0
}

func (j *JSONLookup) splitA(targetHeight int) {
	sz := len(j.A)

	for i := range sz {
		height := len(j.A[i][0])
		if height <= targetHeight {
			continue
		}

		splitHeight := height >> 1

		newTable := make([][]Element, 0, len(j.A[i]))
		ids := make([]string, 0, len(j.A[i]))

		for colI := range j.A[i] {
			newTable = append(newTable, j.A[i][colI][splitHeight:])
			j.A[i][colI] = j.A[i][colI][:splitHeight]
			ids = append(ids, fmt.Sprintf("%s_SPLIT_%d", j.AIds[i][colI], splitHeight))
		}

		j.A = append(j.A, newTable)
		j.AIds = append(j.AIds, ids)

		if j.isFilteredA() {
			j.AFilter = append(j.AFilter, j.AFilter[i][splitHeight:])
			j.AFilter[i] = j.AFilter[i][:splitHeight]
		}
	}
}

func (j *JSONLookup) splitB(targetHeight int) {
	for i := range j.B {

		if len(j.B) != len(j.BIds) {
			panic("haha")
		}

		height := len(j.B[i][0])
		if height <= targetHeight {
			continue
		}

		splitHeight := height >> 1

		newTable := make([][]Element, 0, len(j.B[i]))
		ids := make([]string, 0, len(j.B[i]))

		for colI := range j.B[i] {
			newTable = append(newTable, j.B[i][colI][splitHeight:])
			j.B[i][colI] = j.B[i][colI][:splitHeight]
			ids = append(ids, fmt.Sprintf("%s_SPLIT_%d", j.BIds[i][colI], splitHeight))
		}

		j.B = append(j.B, newTable)
		j.BIds = append(j.BIds, ids)

		if j.isFilteredB() {
			j.BFilter = append(j.BFilter, j.BFilter[i][splitHeight:])
			j.BFilter[i] = j.BFilter[i][:splitHeight]
		}
	}
}

func (j *JSONLookup) splitAll(targetHeight int) {
	for j.heightA() > targetHeight {
		j.splitA(targetHeight)
	}

	for j.heightB() > targetHeight {
		j.splitB(targetHeight)
	}
}

func (j *JSONGlobal) height() int {
	return len(j.Inputs[0])
}

func (j *JSONGlobal) split() (*JSONGlobal, *JSONGlobal) {
	new := &JSONGlobal{
		Inputs:    make([][]Element, len(j.Inputs)),
		InputsIds: make([]string, len(j.InputsIds)),
		Nodes:     j.Nodes,
		Start:     j.Start,
		Stop:      j.Stop,
	}

	splitHeight := j.height() >> 1
	for i := range j.Inputs {
		new.Inputs[i] = j.Inputs[i][splitHeight:]
		j.Inputs[i] = j.Inputs[i][:splitHeight]

		j.Stop = min(splitHeight, j.Stop)
		j.Start = min(splitHeight, j.Start)

		new.Stop = max(0, new.Stop-splitHeight)
		new.Start = max(0, new.Start-splitHeight)

		if j.InputsIds[i] != "" {
			new.InputsIds[i] = fmt.Sprintf("%s_SPLIT_%d", j.InputsIds[i], splitHeight)
		}
	}

	return j, new
}

func (j *JSONGlobal) splitColumns(targetHeight int) []*JSONGlobal {
	res := []*JSONGlobal{j}
	for j.height() > targetHeight {
		cur := make([]*JSONGlobal, 0, len(res)*2)

		for i := range res {
			l, r := res[i].split()
			cur = append(cur, l, r)
		}

		res = cur
	}

	return res
}

func (j *JSONGlobal) isActive() bool {
	return j.Start < j.Stop
}
