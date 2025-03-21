# Use an official Ubuntu image as the base
FROM ubuntu:20.04

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package list and install Python3, pip, and auditd (if needed for testing)
RUN apt-get update && \
    apt-get install -y python3 python3-pip auditd && \
    apt-get clean

# Set the working directory in the container
WORKDIR /app

# Copy the project files into the container
COPY . .

# Install required Python packages (pyyaml for the rule engine)
RUN pip3 install --no-cache-dir pyyaml

# Expose any ports if needed (not necessary for a command-line demo)
# EXPOSE 8080

# Run the main application
CMD ["python3", "main.py"]