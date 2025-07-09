package nri

default allow = false

# Allow if no forbidden arg, env, or mount is present
allow {
  not forbidden_arg
  not forbidden_env
  not forbidden_mount
}

forbidden_arg {
  some i
  input.args[i] == "forbidden-arg"
}

forbidden_env {
  some i
  input.env[i] == "FORBIDDEN=1"
}

forbidden_mount {
  input.mounts != null
  some i
  input.mounts[i].destination == "/forbidden"
} 