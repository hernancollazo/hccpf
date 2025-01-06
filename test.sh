#!/bin/bash

# Run al tests

source ${PWD}/venv/bin/activate
python -m unittest discover -s tests -p "test_*.py"
