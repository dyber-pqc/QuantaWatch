@echo off
REM Windows wrapper so `make <target>` works without installing GNU make.
REM Mirrors the Makefile targets. Requires Git Bash (bash) + cargo on PATH.
REM Run from the repo root, e.g.:  make setup   |   make test
setlocal
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=help"

if /I "%TARGET%"=="help"   goto :help
if /I "%TARGET%"=="setup"  goto :setup
if /I "%TARGET%"=="sync"   goto :sync
if /I "%TARGET%"=="test"   goto :test
if /I "%TARGET%"=="build"  goto :build
if /I "%TARGET%"=="fmt"    goto :fmt
if /I "%TARGET%"=="clippy" goto :clippy

echo Unknown target: %TARGET%
echo.
goto :help

:setup
bash scripts/setup.sh
goto :eof

:sync
bash scripts/sync-dev-notes.sh
goto :eof

:test
cargo test --workspace
goto :eof

:build
cargo build --workspace
goto :eof

:fmt
cargo fmt --all
goto :eof

:clippy
cargo clippy --workspace --all-targets
goto :eof

:help
echo Usage: make ^<target^>
echo.
echo   build      build the whole workspace
echo   clippy     lint all crates
echo   fmt        format all Rust code
echo   help       show this help
echo   setup      one-time: enable repo-tracked git hooks for this clone
echo   sync       regenerate docs/dev-notes/ from the private working notes
echo   test       run the full workspace test suite
goto :eof
