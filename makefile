setup:
	python -m venv venv && \
	. venv/bin/activate && \
	pip install --upgrade pip && \
	pip install -r requirements.txt

run:
	. venv/bin/activate && \
	streamlit run app.py
