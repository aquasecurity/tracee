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
is_elf_file(string){
    decoded_string := base64.decode(string)
    sub_string := substring(decoded_string, 1, 3)
    lower(sub_string) == "elf"
}


k8s_api_server_ip(array) = res {
    environment_vars := array[_]
    contains(environment_vars, "KUBERNETES_SERVICE_HOST")
    res := { "ip_address": environment_vars[i] }
}


default elevate_to_root(eventName) = false
elevate_to_root(eventName) {
    eventName == "commit_creds"
    old_cred_map := get_tracee_argument("old_cred")
    new_cred_map := get_tracee_argument("new_cred")

    old_uid := old_cred_map["Uid"]
    new_uid := new_cred_map["Uid"]

    old_uid != 0
    new_uid == 0
}

default drop_root_permissions(eventName) = false
drop_root_permissions(eventName) {
    eventName == "commit_creds"
    old_cred_map := get_tracee_argument("old_cred")
    new_cred_map := get_tracee_argument("new_cred")

    old_uid := old_cred_map["Uid"]
    new_uid := new_cred_map["Uid"]

    old_uid == 0
    new_uid != 0
}

default process_capabilities_changed(eventName) = false
process_capabilities_changed(eventName) {
    eventName == "commit_creds"
    old_cred_map := get_tracee_argument("old_cred")
    new_cred_map := get_tracee_argument("new_cred")

    old_cap := old_cred_map["CapEffective"]
    new_cap := new_cred_map["CapEffective"]

    old_cap != new_cap
}

default is_host_process = false
is_host_process {
    input.processId == input.hostProcessId
}

default is_not_host_process = false
is_not_host_process {
    input.processId != input.hostProcessId
}
