package formatter

// PrintTableHeaders prints table headers with padding based on their length.
func (f *Formatter) PrintTableHeaders(headers []string) {
	switch len(headers) {
	case 4:
		f.cmd.Printf("%-20s %-15s %-15s %-20s\n",
			headers[0],
			headers[1],
			headers[2],
			headers[3],
		)
	case 5:
		f.cmd.Printf("%-15s %-10s %-20s %-15s %-10s\n",
			headers[0],
			headers[1],
			headers[2],
			headers[3],
			headers[4],
		)
	default:
		f.cmd.Println("Error: Unsupported number of headers.")
	}
}

// PrintTableRow prints a single row with padding matching the header format.
func (f *Formatter) PrintTableRow(row []string) {
	switch len(row) {
	case 4:
		f.cmd.Printf("%-20s %-15s %-15s %-20s\n",
			row[0],
			row[1],
			row[2],
			row[3],
		)
	case 5:
		f.cmd.Printf("%-15s %-10s %-20s %-15s %-10s\n",
			row[0],
			row[1],
			row[2],
			row[3],
			row[4],
		)
	default:
		f.cmd.Println("Error: Unsupported number of columns in row.")
	}
}
