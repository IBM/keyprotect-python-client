.PHONY: dist

dist:
	python setup.py sdist bdist_wheel

publish: dist
	pip install 'twine>=1.5.0'
	twine upload dist/*
	rm -fr build dist .egg *.egg-info

ci: test-init lint

test-init:
	python -m pytest test

lint:
	./pylint.sh