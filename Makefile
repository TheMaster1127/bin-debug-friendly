PYTHON ?= python3

.PHONY: test clean

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

clean:
	rm -rf __pycache__ src/__pycache__ tests/__pycache__ *.stack.bin *-mapped_*
