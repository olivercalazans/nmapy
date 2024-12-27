#!/bin/bash

# Define the file name for the wrapper script
FILE="dataseeker"

# Find the path to the directory containing the os_fingerprint.py file
PATH1=$(find $HOME -name os_fingerprint.py -exec dirname {} \; 2>/dev/null)

# Get the parent directory of PATH1
PATH2=${PATH1%/*}

# Define the installation directory path
DIR="$HOME/.dataseeker/"

# Create the wrapper script with the necessary commands to run the Python script
echo "#!/bin/bash" > $FILE
echo "sudo $DIR/seeker/bin/python3 $DIR/main.py \"\$@\"" >> $FILE

# Move the wrapper script to /usr/bin for global access
sudo mv $FILE /usr/bin

# Grant execution permissions to the wrapper script
sudo chmod +x /usr/bin/$FILE

# Create the main installation directory and subdirectory for the code
mkdir -p $DIR

# Copy all Python files from the found directory to the installation directory
cp "$PATH1/*.py" $DIR

# Copy the LICENSE file from the parent directory to the installation directory, suppressing errors
cp "$PATH2/LICENSE" $DIR 2> /dev/null

# Install required packages for Python virtual environment and pip
sudo apt install python3-venv python3-pip -y

# Create a Python virtual environment inside the installation directory
python3 -m venv "$DIR/seeker"

# Activate the virtual environment
source "$DIR/seeker/bin/activate"

# Install the 'scapy' package inside the virtual environment
pip install scapy

# Deactivate the virtual environment after the installation is complete
deactivate

# Print a completion message
echo 'INSTALLATION COMPLETED'
