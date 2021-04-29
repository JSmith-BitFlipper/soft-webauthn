.PHONY: all venv install-deps freeze lint test coverage wheel upload

all: lint coverage

venv:
	sudo apt-get -y install python-virtualenv python3-virtualenv
	virtualenv -p python3 venv

install-deps:
	pip install -r requirements-dev.lock

freeze:
	@pip freeze | grep -v '^pkg-resources='

lint:
	python3.6 -m flake8 soft_webauthn.py tests
	python3.6 -m pylint --ignore=example_server.py soft_webauthn.py tests

test:
	python3.6 -m pytest -v

coverage:
	coverage run --source soft_webauthn -m pytest tests -x -vv
	coverage report --show-missing --fail-under 100

wheel:
	python3.6 setup.py sdist bdist_wheel
upload:
	twine upload dist/*
