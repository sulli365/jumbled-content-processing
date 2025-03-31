# Use an official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your app code
COPY . .

# Set environment variables (can be overridden in Railway)
ENV OUTPUT_DIR=output_md_files

# Create output directory
RUN mkdir -p ${OUTPUT_DIR}

# Run the app
CMD ["python", "gmail_to_markdown_pipeline.py"]
