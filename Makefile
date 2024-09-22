.PHONY: install example build document


vendor:
	Rscript -e "rextendr::vendor_pkgs()"

document:
	Rscript -e "rextendr::document()"

install:
	Rscript -e "devtools::install()"

example:
	faucet start -w 1 -d example

build:
	cd src/rust && cargo build


