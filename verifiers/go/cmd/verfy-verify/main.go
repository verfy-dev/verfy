// verfy-verify checks a Verfy ledger: verfy-verify LEDGER.jsonl PUBLIC_KEY
package main

import (
	"fmt"
	"os"

	verfy "github.com/verfy-dev/verfy/verifiers/go"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: verfy-verify LEDGER.jsonl PUBLIC_KEY")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	defer f.Close()
	receipts, err := verfy.ReadLedger(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	pub, err := verfy.PublicKey(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	res := verfy.VerifyLedger(receipts, pub)
	// team approvals made with a passkey carry its signature over that call's arguments hash
	checked, approvalProblems := verfy.CheckApprovals(receipts)
	res.Errors = append(res.Errors, approvalProblems...)
	res.OK = len(res.Errors) == 0
	if res.OK {
		fmt.Printf("VERIFIED  %d receipts, signed by %s, chain intact.  head %s\n", res.Count, verfy.KeyID(pub), res.Head)
		if checked > 0 {
			fmt.Printf("          %d team approval(s) signed with a passkey: each signature covers that call's arguments hash.\n", checked)
		}
		return
	}
	fmt.Printf("FAILED  %d problem(s) in %d receipts:\n", len(res.Errors), res.Count)
	for _, p := range res.Errors {
		fmt.Printf("  #%v  %s\n", p.Seq, p.Error)
	}
	os.Exit(1)
}
