package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management for traceectl",
	Long: `Policy Management:
  	- traceectl policy create <policy_file>
  	- traceectl policy describe <policy_name>
  	- traceectl policy list
  	- traceectl policy update <updated_policy_file>
	- traceectl policy delete <policy_name>
  	- traceectl policy enable <policy_name>
  	- traceectl policy disable <policy_name>
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("policy called")
	},
}

func init() {
	policyCmd.AddCommand(createCmd)
	policyCmd.AddCommand(describePolicyCmd)
	policyCmd.AddCommand(listPolicyCmd)
	policyCmd.AddCommand(updateCmd)
	policyCmd.AddCommand(deleteCmd)
	policyCmd.AddCommand(enableCmd)
	policyCmd.AddCommand(disableCmd)
}

var createCmd = &cobra.Command{
	Use:   "create <policy_file>",
	Short: "Create a policy",
	Long:  `Creates a new policy from the YAML file specified by  < policy_file > .`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("create called")
	},
}
var describePolicyCmd = &cobra.Command{
	Use:   "describe <policy_name>",
	Short: "Describe a policy",
	Long:  `Retrieves the details of a specific policy by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("describe called")
	},
}

var listPolicyCmd = &cobra.Command{
	Use:   "list",
	Short: "List policies",
	Long:  `Lists all available policies, providing a brief summary of each.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("list called")
	},
}

var updateCmd = &cobra.Command{
	Use:   "update <updated_policy_file>",
	Short: "update a policy",
	Long:  `Updates an existing policy from the YAML file specified by < updated_policy_file > .`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("update called")
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete <policy_name>",
	Short: "Delete a policy",
	Long:  `Removes a policy by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("delete called")
	},
}

var enableCmd = &cobra.Command{
	Use:   "enable <policy_name>",
	Short: "Enable a policy",
	Long:  `Enables a policy by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("enable called")
	},
}

var disableCmd = &cobra.Command{
	Use:   "disable <policy_name>",
	Short: "Disable a policy",
	Long:  `Disables a policy by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("disable called")
	},
}
