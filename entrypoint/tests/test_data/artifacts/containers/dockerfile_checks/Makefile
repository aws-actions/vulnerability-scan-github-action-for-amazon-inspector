# build and scan vulnerable image
all: build scan

# build the image under test / development
build:
	docker build . -t dev:latest

# scan image with inspector
scan:
	inspector-sbomgen container --image "dev:latest" --scan-sbom --scanners dockerfile -o inspector-scan.json
