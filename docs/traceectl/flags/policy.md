# `policy` Flag

The `--policy` flag is used to specify the polices to include for the command's stream events. If this flag is set it must have a valid policy name loaded into tracee.

- **""**: This is the default policy, which means that the command's streamed events will display on the terminal all events capture by tracee. This is convenient for users who want to see immediate results directly in their console.
  
  Example:

  ```sh
  traceectl stream --policy policy1
  ```

  In this example, the command outputs the streamed events from a specific policy to the terminal.

- **Multi Policy**: You can use the `--policy` flag to specify multiple policies to include for the command's stream events. This is useful if you want to make batter analysis for different needs
  
  Example:

  ```sh
  traceectl stream --policy policy1 policy2
  ```

In this example, the command outputs the streamed events from a specific policies to the terminal. This is especially helpful for logging purposes or when working with large amounts of data that need to be sorted for further processing.
