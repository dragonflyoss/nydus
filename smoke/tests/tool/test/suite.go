package test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	prefix = "Test"

	flagSync = uint8(1)
)

func Sync(opts *options) {
	opts.flag |= flagSync
}

type Option func(opts *options)

type options struct {
	flag uint8
}

type Case func(*testing.T)

type Generator func() (name string, testCase Case)

// This is a testing framework that helps coders organize test cases into test suite.
//
// It provides both dynamic and static/common way to define test cases. The dynamic
// way generates test cases by customized generator in runtime. The static way executes
// cases which are defined in compiling.
//
// It also provides both synchronized and asynchronous way to run test cases. The
// asynchronous/synchronized control is suite-leveled.
//
// Compared with github.com/onsi/ginkgo, this framework provides simpler way to organize
// cases into suite, which requires less learing of terms and less nested definitions.
// Moreover, the asynchronous run is more golang-natived, which requires no other binary.
//
// Compared with github.com/stretchr/testify, this framework provides asynchronous mode
// and dynamic way to generate cases.
//
// Example1: synchronized way
//
//        import (
//            "fmt"
//            "testing"
//
//            "github.com/stretchr/testify/require"
//        )
//
//        type TestSuite struct{}
//
//        func (s *TestSuite) TestOk(t *testing.T) {
//            require.Equal(t, 1, 1)
//        }
//
//        func (s *TestSuite) TestFail(t *testing.T) {
//            require.Equal(t, 1, 2)
//        }
//
//        func (s *TestSuite) TestDynamicTest() TestGenerator {
//            caseNum := 0
//            return func() (name string, testCase TestCase) {
//                if caseNum <= 5 {
//                    testCase = func(t *testing.T) {
//                        require.Equal(t, 1, 2)
//                    }
//                }
//                caseNum++
//                return fmt.Sprintf("dynamic_test_%v", caseNum), testCase
//            }
//        }
//
//        func Test1(t *testing.T) {
//            Run(t, &TestSuite{}, Sync)
//        }
//
// Output:
//        `go test -v --parallel 4`
//            1. The cases are serialized executed.
//            2. The dynamic tests are generated and executed.
//
//        === RUN   Test1
//        === RUN   Test1/dynamic_test_1
//        === RUN   Test1/dynamic_test_2
//        === RUN   Test1/dynamic_test_3
//        === RUN   Test1/dynamic_test_4
//        === RUN   Test1/dynamic_test_5
//        === RUN   Test1/dynamic_test_6
//        === RUN   Test1/TestFail
//            suite_test.go:18:
//                        Error Trace:    suite_test.go:18
//                        Error:          Not equal:
//                                        expected: 1
//                                        actual  : 2
//                        Test:           Test1/TestFail
//        === RUN   Test1/TestOk
//        --- FAIL: Test1 (0.00s)
//            --- PASS: Test1/dynamic_test_1 (0.00s)
//            --- PASS: Test1/dynamic_test_2 (0.00s)
//            --- PASS: Test1/dynamic_test_3 (0.00s)
//            --- PASS: Test1/dynamic_test_4 (0.00s)
//            --- PASS: Test1/dynamic_test_5 (0.00s)
//            --- PASS: Test1/dynamic_test_6 (0.00s)
//            --- FAIL: Test1/TestFail (0.00s)
//            --- PASS: Test1/TestOk (0.00s)
//
// Example2: asynchronized way
//
//        import (
//            "fmt"
//            "testing"
//            "time"
//        )
//
//        type AsyncTestSuite struct{}
//
//        func (s *AsyncTestSuite) Test1(t *testing.T) {
//            for i := 0; i < 5; i++ {
//                time.Sleep(time.Second)
//            }
//        }
//
//        func (s *AsyncTestSuite) Test2(t *testing.T) {
//            for i := 0; i < 5; i++ {
//                time.Sleep(time.Second)
//            }
//        }
//
//        func (s *AsyncTestSuite) Test3(t *testing.T) {
//            for i := 0; i < 5; i++ {
//                time.Sleep(time.Second)
//            }
//        }
//
//        func (s *AsyncTestSuite) TestDynamicTest() TestGenerator {
//            caseNum := 0
//            return func() (name string, testCase TestCase) {
//                if caseNum <= 5 {
//                    testCase = func(t *testing.T) {
//                        for i := 0; i < 5; i++ {
//                            time.Sleep(time.Second)
//                        }
//                    }
//                }
//                caseNum++
//                return "", testCase
//            }
//        }
//
//        func Test1(t *testing.T) {
//            Run(t, &AsyncTestSuite{})
//        }
//
// Output:
//        `go test -v --parallel 4`
//            1. The cases are parallel executed, which leads to random completion.
//            2. The dynamic tests are named automicly in lack of customized name.
//
//            --- PASS: Test1 (0.00s)
//                --- PASS: Test1/TestDynamicTest_4 (5.00s)
//                --- PASS: Test1/Test1 (5.00s)
//                --- PASS: Test1/TestDynamicTest_6 (5.00s)
//                --- PASS: Test1/TestDynamicTest_5 (5.00s)
//                --- PASS: Test1/TestDynamicTest_2 (5.00s)
//                --- PASS: Test1/TestDynamicTest_3 (5.00s)
//                --- PASS: Test1/TestDynamicTest_1 (5.00s)
//                --- PASS: Test1/Test3 (5.00s)
//                --- PASS: Test1/Test2 (5.00s)
//
//
func Run(t *testing.T, suite interface{}, opts ...Option) {

	cases := reflect.ValueOf(suite)
	if cases.Type().Kind() != reflect.Pointer || !reflect.Indirect(cases).IsValid() {
		panic("test suite should be &struct{}")
	}

	var option options
	for _, opt := range opts {
		opt(&option)
	}

	ifTests := func(method *reflect.Method) bool {
		return strings.HasPrefix(method.Name, prefix) &&
			method.Type.NumIn() == 1 &&
			method.Type.NumOut() == 1 &&
			method.Type.Out(0).
				AssignableTo(
					reflect.TypeOf(func() (n string, t Case) { return "", nil }))
	}
	ifTest := func(method *reflect.Method) bool {
		return strings.HasPrefix(method.Name, prefix) &&
			method.Type.NumIn() == 2 &&
			method.Type.NumOut() == 0 &&
			method.Type.In(1).AssignableTo(reflect.TypeOf(&testing.T{}))
	}

	casesMeta := reflect.TypeOf(suite)
	for idx := 0; idx < casesMeta.NumMethod(); idx++ {
		testCase := cases.Method(idx)
		meta := casesMeta.Method(idx)

		if ifTests(&meta) {
			factory, ok := testCase.Interface().(func() Generator)
			if !ok || factory == nil {
				continue
			}
			runDynamicTest(t, meta.Name, factory(), option.flag)
			continue
		}

		if ifTest(&meta) {
			testCase, ok := testCase.Interface().(func(*testing.T))
			if !ok {
				continue
			}
			runTest(t, meta.Name, testCase, option.flag)
		}
	}
}

func runTest(t *testing.T, name string, testCase Case, flags uint8) {
	t.Run(name, func(t *testing.T) {
		if flags&flagSync == 0 {
			t.Parallel()
		}
		testCase(t)
	})
}

func runDynamicTest(t *testing.T, name string, generator Generator, flags uint8) {
	count := 0
	for caseName, testCase := generator(); testCase != nil; caseName, testCase = generator() {
		count++
		if len(caseName) == 0 {
			caseName = fmt.Sprintf("%s_%v", name, count)
		}

		runTest(t, caseName, testCase, flags)
	}
}
