package formatter

func (f *Formatter) PrintJson(response string) {
	f.cmd.Printf(response)
}
