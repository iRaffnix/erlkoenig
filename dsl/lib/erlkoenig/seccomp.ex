#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Erlkoenig.Seccomp do
  @moduledoc """
  Seccomp profile definitions for Erlkoenig containers.

  Profiles:
    - `:strict`     — Minimal syscalls (read, write, exit, sigreturn, etc.)
    - `:standard`   — Common server syscalls (network, files, mmap, clock)
    - `:permissive` — Most syscalls allowed, only dangerous ones blocked

  Each profile returns a term map with `:profile` and `:syscalls` keys.
  """

  @strict_syscalls [
    :read, :write, :close, :exit, :exit_group, :rt_sigreturn,
    :brk, :mmap, :munmap, :mprotect, :sigaltstack,
    :getrandom, :clock_gettime, :futex
  ]

  @standard_syscalls @strict_syscalls ++ [
    :openat, :fstat, :stat, :lstat, :lseek, :pread64, :pwrite64,
    :readv, :writev, :access, :pipe, :pipe2, :dup, :dup2, :dup3,
    :socket, :connect, :accept, :accept4, :bind, :listen,
    :sendto, :recvfrom, :sendmsg, :recvmsg,
    :setsockopt, :getsockopt, :getsockname, :getpeername,
    :epoll_create1, :epoll_ctl, :epoll_wait, :epoll_pwait,
    :poll, :ppoll, :select, :pselect6,
    :fcntl, :ioctl,
    :getpid, :gettid, :getuid, :getgid, :geteuid, :getegid,
    :set_tid_address, :set_robust_list,
    :clone, :wait4, :nanosleep, :clock_nanosleep,
    :sched_yield, :sched_getaffinity,
    :madvise, :mremap, :mincore,
    :prctl, :arch_prctl, :rseq,
    :tgkill, :rt_sigaction, :rt_sigprocmask
  ]

  @blocked_dangerous [
    :mount, :umount2, :pivot_root, :chroot,
    :ptrace, :process_vm_readv, :process_vm_writev,
    :init_module, :finit_module, :delete_module,
    :reboot, :swapon, :swapoff,
    :kexec_load, :kexec_file_load,
    :bpf, :perf_event_open, :userfaultfd,
    :keyctl, :request_key, :add_key
  ]

  def get(:strict) do
    %{profile: :strict, syscalls: @strict_syscalls}
  end

  def get(:standard) do
    %{profile: :standard, syscalls: @standard_syscalls}
  end

  def get(:network) do
    %{profile: :network, syscalls: @standard_syscalls}
  end

  def get(:permissive) do
    %{profile: :permissive, blocked: @blocked_dangerous}
  end

  def list, do: [:strict, :standard, :network, :permissive]
end
