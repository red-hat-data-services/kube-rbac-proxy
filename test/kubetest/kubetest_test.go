/*
Copyright 2017 Frederic Branczyk All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubetest

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestScenarioCleanupFailure(t *testing.T) {
	if os.Getenv("KUBE_RBAC_PROXY_CLEANUP_TEST") == "1" {
		continued := false
		scenario := Scenario{
			Name: "cleanup-failure",
			Given: func(ctx *ScenarioContext) error {
				ctx.AddCleanUp(func() error { return errors.New("delete deployment default/example: test failure") })
				ctx.AddCleanUp(func() error { continued = true; return nil })
				return nil
			},
		}
		passed := scenario.Run(t)
		if passed || !continued {
			t.Fatalf("cleanup result: passed=%v continued=%v", passed, continued)
		}
		t.Log("remaining cleanup ran and scenario returned false")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestScenarioCleanupFailure$", "-test.v")
	cmd.Env = append(os.Environ(), "KUBE_RBAC_PROXY_CLEANUP_TEST=1")
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected a test failure, got %v:\n%s", err, output)
	}
	for _, want := range []string{
		"cleanup action 1 failed: delete deployment default/example: test failure",
		"--- FAIL: TestScenarioCleanupFailure/cleanup-failure",
		"remaining cleanup ran and scenario returned false",
	} {
		if !strings.Contains(string(output), want) {
			t.Errorf("missing %q in output:\n%s", want, output)
		}
	}
}
