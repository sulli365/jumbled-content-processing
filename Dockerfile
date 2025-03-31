# Use official Python base image
FROM python:3.11-slim

# Set working directory in the container
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your app
COPY . .

# Set environment variables (optional fallback defaults)
ENV TRACK_FILE=processed_links.json
ENV LOG_FILE=pipeline.log

# Run your app
CMD ["python", "gmail_to_markdown_pipeline.py"]
