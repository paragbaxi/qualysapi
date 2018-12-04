init:
	pip install -r reqs/dev-requirements.txt

lint:
	# exit-zero treats all errors as warnings.  The GitHub editor is 127 chars wide
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
ifeq ($(TRAVIS_PYTHON_VERSION), 3.6)
		echo "Only fail lint for Python3.6"
else
		# stop the build if there are Python syntax errors or undefined names
		flake8 . --count --select=E901,E999,F821,F822,F823 --show-source --statistics
endif

test:
	py.test -rfp --cov=qualysapi -vv --cov-report term-missing