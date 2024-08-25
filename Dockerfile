# Use the official Python 3 image from the Docker Hub
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install any necessary dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Expose the port that the SSH honeypot will be listening on
EXPOSE 2000

# Run the SSH honeypot script
CMD ["python3", "honey_pot.py", "-a", "127.0.0.1", "-p", "2000", "-u", "root", "-pw", "root"]