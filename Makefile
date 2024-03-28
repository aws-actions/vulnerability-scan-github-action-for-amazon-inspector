run:
	docker build . -t inspector-action:latest
	docker run -it inspector-action:latest

test:
	cd entrypoint; python3 -m unittest discover -v -s ./

coverage:
	cd entrypoint && \
	coverage run -m unittest discover -v -s ./ && \
	coverage report
