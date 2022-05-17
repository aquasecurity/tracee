package tracee.helpers

get_tracee_argument(arg_name) = res {
	arg := input.args[_]
	arg.name == arg_name
	res := arg.value
}

default is_file_write(flags) = false

is_file_write(flags) {
	contains(lower(flags), "o_wronly")
}

is_file_write(flags) {
	contains(lower(flags), "o_rdwr")
}

default is_file_read(flags) = false

is_file_read(flags) {
	contains(lower(flags), "o_rdonly")
}

is_file_read(flags) {
	contains(lower(flags), "o_rdwr")
}

default is_elf_file(string) = false

is_elf_file(string) {
	decoded_string := base64.decode(string)
	sub_string := substring(decoded_string, 1, 3)
	lower(sub_string) == "elf"
}
