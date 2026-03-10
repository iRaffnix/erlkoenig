" Vim syntax file
" Language:    Erlkoenig DSL (Elixir-based)
" Maintainer:  erlkoenig
" Last Change: 2026-03-09

if exists('b:current_syntax')
  finish
endif

" ── Base Elixir syntax ──

syn keyword elixirKeyword       do end def defp defmodule use import alias
      \ require fn when in and or not true false nil after
      \ raise rescue try catch if else cond case for with
hi def link elixirKeyword       Keyword

syn keyword elixirSelf          __MODULE__ __DIR__ __ENV__ __CALLER__
hi def link elixirSelf          Identifier

" Module names
syn match   elixirModule        /\v<[A-Z]\w*(\.[A-Z]\w*)*/
hi def link elixirModule        Type

" Atoms
syn match   elixirAtom          /\v:\w+[?!]?/
hi def link elixirAtom          Constant

" Strings
syn region  elixirString        start=/"/ skip=/\\"/ end=/"/ contains=elixirInterp,erlkoenigPath
syn region  elixirHeredoc       start=/"""/ end=/"""/ contains=elixirInterp
hi def link elixirString        String
hi def link elixirHeredoc       String

" String interpolation
syn region  elixirInterp        matchgroup=elixirInterpDelim start=/#{/ end=/}/ contained contains=TOP
hi def link elixirInterpDelim   Special

" Charlists
syn region  elixirCharlist      start=/'/ skip=/\\'/ end=/'/
hi def link elixirCharlist      String

" Sigils
syn match   elixirSigil         /\~[a-zA-Z][("\/|{<\[]\S*[)"\/|}>\]]/
hi def link elixirSigil         String

" Numbers
syn match   elixirNumber        /\v<\d[\d_]*(\.\d[\d_]*)?(e[+-]?\d+)?>/
syn match   elixirNumber        /\v<0x[0-9a-fA-F_]+>/
syn match   elixirNumber        /\v<0b[01_]+>/
syn match   elixirNumber        /\v<0o[0-7_]+>/
hi def link elixirNumber        Number

" Comments
syn match   elixirComment       /#.*$/ contains=elixirTodo
syn keyword elixirTodo          TODO FIXME XXX HACK NOTE contained
hi def link elixirComment       Comment
hi def link elixirTodo          Todo

" Module attributes
syn match   elixirAttribute     /@\w\+/
hi def link elixirAttribute     PreProc

" Operators
syn match   elixirOperator      /|>/
syn match   elixirOperator      /<>/
syn match   elixirOperator      /++/
syn match   elixirOperator      /->/
syn match   elixirOperator      /=>/
syn match   elixirOperator      /=\~/
syn match   elixirOperator      /&&/
syn match   elixirOperator      /||/
syn match   elixirOperator      /\\\\/
hi def link elixirOperator      Operator

" Map keys
syn match   elixirMapKey        /\v\w+\ze:/
hi def link elixirMapKey        Label

" ── Erlkoenig DSL ──

" Block-level keywords
syn keyword erlkoenigBlock       container defaults watch guard
hi def link erlkoenigBlock       Statement

" Container properties
syn keyword erlkoenigProperty    binary ip ports args env limits seccomp
      \ restart files file dns_name firewall firewall_term
      \ health_check zone
hi def link erlkoenigProperty    Function

" Watch properties
syn keyword erlkoenigProperty    counter interval on_alert

" Guard properties
syn keyword erlkoenigProperty    detect ban_duration whitelist cleanup_interval

" Firewall block-level keywords
syn keyword erlkoenigFwBlock     chain
hi def link erlkoenigFwBlock     Statement

" Firewall properties
syn keyword erlkoenigFwProp      counters set
      \ accept accept_tcp accept_udp accept_tcp_range accept_udp_range
      \ accept_from accept_protocol
      \ reject_tcp
      \ drop_from drop_if_in_set
      \ connlimit_drop log_and_drop log_and_reject
hi def link erlkoenigFwProp      Function

" Well-known profile atoms (highlighted distinctly)
syn match   erlkoenigProfile     /\v:(strict|standard|permissive|open|none|default|network)>/
syn match   erlkoenigProfile     /\v:(on_failure|always|never|permanent|no_restart)>/
syn match   erlkoenigProfile     /\v:(log|drop|accept|reject|isolate)>/
syn match   erlkoenigProfile     /\v:(established|icmp|icmpv6|loopback|all)>/
syn match   erlkoenigProfile     /\v:(input|output|forward|prerouting|postrouting)>/
syn match   erlkoenigProfile     /\v:(dmz|internal|external)>/
hi def link erlkoenigProfile     Special

" IP address tuples
syn match   erlkoenigIP          /{\s*\d\+\s*,\s*\d\+\s*,\s*\d\+\s*,\s*\d\+\s*}/
hi def link erlkoenigIP          Number

" Limit keywords
syn keyword erlkoenigLimitKey    cpu memory pids pps bps io_weight
hi def link erlkoenigLimitKey    Type

" Option keywords
syn keyword erlkoenigOption      threshold window allow_tcp allow_udp hook policy
      \ timeout burst limit counter port retries
hi def link erlkoenigOption      Label

" use Erlkoenig.* (module import line)
syn match   erlkoenigUse         /\vuse\s+Erlkoenig\.\w+/
hi def link erlkoenigUse         Include

" File paths inside strings
syn match   erlkoenigPath        /\/[a-zA-Z0-9_./-]\+/ contained
hi def link erlkoenigPath        Directory

" ── Sync ──
syn sync minlines=50

let b:current_syntax = 'erlkoenig'
