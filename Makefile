.PHONY: install run test

install:
	python3 -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip setuptools wheel && python -m pip install -r requirements.txt

run:
	. .venv/bin/activate && python app.py

test:
	. .venv/bin/activate && python -m pytest -q
