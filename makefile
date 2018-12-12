make:
	pip install -r requirements.txt
	python2 HTTP_detector.py

test:
	python2 TestCases.py