" Vim compiler file
" Language:		Test::Unit - Ruby Unit Testing Framework
" Maintainer:		Doug Kearns <dougkearns@gmail.com>
" Info:			$Id: rubyunit.vim,v 1.9 2008/08/09 17:55:13 vimboss Exp $
" URL:			http://vim-ruby.rubyforge.org
" Anon CVS:		See above site
" Release Coordinator:	Doug Kearns <dougkearns@gmail.com>

if exists("current_compiler")
  finish
endif
let current_compiler = "rubyunit"

if exists(":CompilerSet") != 2		" older Vim always used :setlocal
  command -nargs=* CompilerSet setlocal <args>
endif

let s:cpo_save = &cpo
set cpo-=C

CompilerSet makeprg=testrb

CompilerSet errorformat=\%W\ %\\+%\\d%\\+)\ Failure:,
			\%C%m\ [%f:%l]:,
			\%E\ %\\+%\\d%\\+)\ Error:,
			\%C%m:,
			\%C\ \ \ \ %f:%l:%.%#,
			\%C%m,
			\%Z\ %#,
			\%-G%.%#

let &cpo = s:cpo_save
unlet s:cpo_save

" vim: nowrap sw=2 sts=2 ts=8:
