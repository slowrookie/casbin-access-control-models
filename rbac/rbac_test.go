package rbac

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"testing"
	"time"
)

func TestRbac(t *testing.T) {
	m, _ := model.NewModelFromFile("./rbac_model.conf")
	e, _ := casbin.NewEnforcer(m, false)

	roles := []string{"admin", "manager", "developer", "tester"}
	for i := 0; i < 2500; i++ {
		for _, role := range roles {
			e.AddPolicy(fmt.Sprintf("%s_project:%d", role, i), fmt.Sprintf("/projects/%d", i), "GET")
		}
		jasmineRole := fmt.Sprintf("%s_project:%d", roles[0], i)
		e.AddGroupingPolicy("jasmine", jasmineRole)
	}

	e.AddGroupingPolicy("abu", "manager_project:1")
	//e.AddGroupingPolicy("abu", "manager_project:2499")

	request := func(subject, object, action string) {
		t0 := time.Now()
		resp, _ := e.Enforce(subject, object, action)
		tElapse := time.Since(t0)
		fmt.Printf("RESPONSE %-10s %s\t %s : %5v IN: %+v \n", subject, object, action, resp, tElapse)
		if tElapse > time.Millisecond*100 {
			fmt.Printf("More than 100 milliseconds for %s %s %s : %+v \n", subject, object, action, tElapse)
		}
	}

	sub := "abu"
	obj := "/projects/1"
	act := "GET"
	ok, err := e.Enforce(sub, obj, act)
	if nil != err {
		panic(err)
	}
	fmt.Printf("%s access %s use %s , %v \n", sub, obj, act, ok)
	request(sub, obj, act)
	request("abu", "/projects/1", "GET")
	request("jasmine", "/projects/1", "GET")
	request("jasmine", "/projects/2499", "GET")
	request("jasmine", "/projects/2499", "GET")
}
