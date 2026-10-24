# The guest runner, built on every target including cross builds. The guest .wbx
# it takes is OS-independent, so CI builds one on Linux and runs it through the
# Windows host (under wine, and natively on a Windows runner).
run_guest = executable('run_guest', 'run_guest.c',
  dependencies: minibox_host_dep,
  install: false,
)

# The threads guest's runner (../threads), built here for the same reason: its
# guest's fault handler runs inside the host's own on Windows, and only a
# Windows run shows what that does.
run_threads = executable('run_threads', '../threads/run_threads.c',
  dependencies: minibox_host_dep,
  install: false,
)
