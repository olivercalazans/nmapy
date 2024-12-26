#!/bin/bash

# Define the file name for the wrapper script
FILE="dataseeker"
# Define the path for the installation directory
DICT="$HOME/.dataseeker/"

# Create the wrapper script with the necessary commands to run the Python script
echo "#!/bin/bash" > $FILE
echo "sudo $HOME/.dataseeker/code/seeker/bin/python3 $HOME/.dataseeker/code/main.py \"\$@\"" >> $FILE

# Move the wrapper script to /usr/bin for global access
sudo mv $FILE /usr/bin

# Give execution permissions to the wrapper script
sudo chmod +x /usr/bin/$FILE

# Create the main installation directory and subdirectory for code
mkdir $DICT && mkdir "$DICT/code/"

# Move all contents from the '../code' directory into the newly created directory
mv ../code/* "$DICT/code"

# Move all other contents from the parent directory to the installation directory, suppressing errors
mv ../* $DICT 2> /dev/null

# Install necessary packages for Python virtual environment and pip
sudo apt install python3-venv python3-pip -y

# Create a Python virtual environment inside the 'code' directory
python3 -m venv "$DICT/code/seeker"

# Activate the virtual environment
source "$DICT/code/seeker/bin/activate"

# Install the 'scapy' package inside the virtual environment
pip install scapy

# Deactivate the virtual environment after installation is complete
deactivate

# Remove the original 'dataseeker' directory, as it's no longer needed
rm -rf ../../dataseeker
