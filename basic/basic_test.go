package basic

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"testing"
)

func TestBasic(t *testing.T) {
	e, err := casbin.NewEnforcer("./basic_model.conf", "./basic_policy.csv")

	if nil != err {
		panic(err)
	}

	sub := "alice"
	obj := "data2"
	act := "read"
	e.EnableLog(true)
	ok, err := e.Enforce(sub, obj, act)
	if nil != err {
		panic(err)
	}

	fmt.Printf("%s access %s use %s , %v ", sub, obj, act, ok)

	results, err := e.BatchEnforce([][]interface{}{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"jack", "data3", "read"}})
	fmt.Printf("%#+v", results)
}
