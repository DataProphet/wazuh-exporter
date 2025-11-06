FROM python:3-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the exporter script
COPY wazuh_exporter.py .

# Set default port
ENV PORT 9115

# Expose the port
EXPOSE 9115

# Run the exporter
CMD ["python", "wazuh_exporter.py"]
