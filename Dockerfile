# Location: email_validator_project/Dockerfile
# 1. Start with an official Python base image.
FROM python:3.10-slim
# 2. Set the working directory inside the container.
WORKDIR /app
# 3. Copy the requirements file first to leverage Docker's build cache.
COPY requirements.txt .
# 4. Install the Python dependencies.
RUN pip install --no-cache-dir --upgrade -r requirements.txt
# 5. Copy your application code into the container.
COPY app.py .
COPY main.py .
# 6. Expose the port the app will run on inside the container.
EXPOSE 8000
# 7. The command to start the Uvicorn server when the container launches.
#    --host 0.0.0.0 is crucial to make it accessible from outside the container.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]