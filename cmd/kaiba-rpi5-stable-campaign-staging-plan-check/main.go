// Command kaiba-rpi5-stable-campaign-staging-plan-check validates public plan
// bytes on stdin with the production contract. It opens no paths or devices.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

const maximumPlanBytes = 4 * 1024 * 1024

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, input io.Reader, output, diagnostics io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(diagnostics, "usage: kaiba-rpi5-stable-campaign-staging-plan-check < staging-plan.json")
		return 2
	}
	encoded, err := io.ReadAll(io.LimitReader(input, maximumPlanBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPlanBytes {
		fmt.Fprintln(diagnostics, "staging plan: bounded stdin read failed")
		return 1
	}
	plan, err := campaignmedia.ParseStagingPlan(encoded)
	if err != nil {
		fmt.Fprintln(diagnostics, "staging plan:", err)
		return 1
	}
	if err := json.NewEncoder(output).Encode(map[string]any{
		"status": "valid", "plan_digest": plan.PlanDigest,
		"destructive_staging_ready": false,
	}); err != nil {
		fmt.Fprintln(diagnostics, "staging plan: write verification failed")
		return 1
	}
	return 0
}
